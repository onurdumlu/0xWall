#!/usr/bin/env python3

"""
Raspberry Pi - Otomatik 'Pcap Yükleme' İstemcisi (15 Saniye Modu)
Bu script:
1. Paketleri toplar ve her 15 SANİYEDE BİR sunucuya yükler.
2. Sunucudan gelen yanıtla saldırganı engeller.
3. Dashboard entegrasyonu için log tutar.
"""

import scapy.all as scapy
import requests
import subprocess
import threading
import time
import os
import json
from datetime import datetime

# --- AYARLAR ---
# Dinlenecek arayüz (Kendi ağ kartınıza göre değiştirin, örn: 'wlan0' veya 'eth0')
LISTEN_INTERFACE = "eth1"

# Sunucunuzun (Colab) Ngrok adresi (HER COLAB BAŞLATTIĞINDA BURAYI GÜNCELLE!)
LLM_API_URL = "https://unrevolted-caleb-semipreserved.ngrok-free.dev/analyze"

# 🔥 SÜRE AYARLANDI: 15 SANİYE
BATCH_INTERVAL_SECONDS = 15 

# Dashboard'un okuyacağı log dosyası
LOG_FILE = "firewall_logs.json"

# --- Global Değişkenler ve Kilitleme ---
packet_batch = []
batch_lock = threading.Lock()
blocked_ips_cache = set()

def check_privileges():
    """Script'in root (sudo) yetkileriyle çalışıp çalışmadığını kontrol eder."""
    if os.geteuid() != 0:
        print("❌ HATA: Root (sudo) yetkileri gereklidir.")
        print("Lütfen 'sudo python3 client.py' olarak çalıştırın.")
        exit(1)

def save_log_to_file(ip_address, reason, action):
    """Olayı JSON dosyasına kaydeder (Dashboard için)."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip_address,
        "reason": reason,
        "action": action
    }
    
    logs = []
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
    except (json.JSONDecodeError, ValueError):
        logs = []

    logs.insert(0, entry)
    logs = logs[:200] # Son 200 kayıt tutulur
    
    try:
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"⚠️ Log dosyasına yazılamadı: {e}")

def block_ip(ip_address, reason):
    """Verilen IP adresini 'iptables' kullanarak engeller."""
    if ip_address in blocked_ips_cache:
        return

    print(f"🚫 [EYLEM] IP Engelleniyor: {ip_address} (Neden: {reason})")
    try:
        # Saldırganı engelle
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip_address, "-j", "DROP"], check=True)
        blocked_ips_cache.add(ip_address)
        
        # Log dosyasına yaz
        save_log_to_file(ip_address, reason, "BLOCKED")
        
        print(f"✅ [Başarılı] IP {ip_address} engellendi.")
    except Exception as e:
        print(f"❌ [iptables Hatası] {e}")

def batch_sender_loop():
    """
    (Arka Plan Thread'i)
    Her 15 saniyede bir paketleri sunucuya gönderir.
    """
    pcap_filepath = "temp_batch.pcap" 

    while True:
        print(f"\n... {BATCH_INTERVAL_SECONDS} saniye sonra analiz gönderilecek ...")
        time.sleep(BATCH_INTERVAL_SECONDS)

        batch_to_save = []

        with batch_lock:
            if not packet_batch:
                print(f"🕒 [{time.strftime('%H:%M:%S')}] Analiz edilecek paket yok. Beklemede.")
                continue

            batch_to_save = packet_batch.copy()
            packet_batch.clear()

        print(f"📦 [{time.strftime('%H:%M:%S')}] {len(batch_to_save)} paket Colab'a gönderiliyor...")

        try:
            # 1. Pcap dosyasını oluştur
            scapy.utils.wrpcap(pcap_filepath, batch_to_save)
            
            # 2. Sunucuya yükle (Timeout süresini 20sn yaptık, rahat yetişsin diye)
            with open(pcap_filepath, 'rb') as f:
                files = {'pcap_file': (pcap_filepath, f, 'application/vnd.tcpdump.pcap')}
                response = requests.post(LLM_API_URL, files=files, timeout=20)
                response.raise_for_status()

            # 3. Yanıtı İşle
            data = response.json()
            ips_to_block = data.get('blocked_ips')
            reason = data.get('reason', 'LLM Tespiti')

            if ips_to_block:
                print(f"🚨 ALARM! {len(ips_to_block)} IP için engelleme emri geldi.")
                for ip in ips_to_block:
                    block_ip(ip, reason)
            else:
                print(f"🧠 [LLM] Trafik temiz. ({data.get('reason')})")

        except requests.exceptions.Timeout:
            print("❌ [Hata] Sunucu yanıt vermedi (Timeout). Colab yoğun olabilir.")
        except requests.exceptions.RequestException as e:
            print(f"❌ [Hata] Bağlantı hatası: {e}")
        except Exception as e:
            print(f"❌ [Genel Hata] {e}")

        finally:
            if os.path.exists(pcap_filepath):
                os.remove(pcap_filepath)

def packet_sniffer(packet):
    """(Ana Thread) Paket yakalama"""
    if not (packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP)): return
    # Sadece SYN (yeni bağlantı) paketlerini yakala
    if packet[scapy.TCP].flags != 'S': return 

    try:
        src_ip = packet[scapy.IP].src
        
        # Filtreler (Kendimizi, yerel ağı engellemeyelim)
        if packet[scapy.IP].is_private_addr(src_ip) or \
           packet[scapy.IP].is_multicast(src_ip) or \
           packet[scapy.IP].is_loopback(src_ip):
            return

        if src_ip in blocked_ips_cache: return

        with batch_lock:
            packet_batch.append(packet)

    except Exception as e:
        pass

def main():
    check_privileges()
    print(f"--- FİREWALL İSTEMCİSİ AKTİF ({BATCH_INTERVAL_SECONDS} sn Modu) ---")
    print(f"Hedef API: {LLM_API_URL}")
    print("Dashboard ile entegre çalışıyor...")

    try:
        sender_thread = threading.Thread(target=batch_sender_loop, daemon=True)
        sender_thread.start()

        print("Paket dinleyici başlatıldı...")
        scapy.sniff(
            iface=LISTEN_INTERFACE,
            prn=packet_sniffer,
            filter="tcp and (tcp[tcpflags] & tcp-syn != 0)",
            store=False
        )
    except KeyboardInterrupt:
        print("\nÇıkış yapılıyor...")

if __name__ == "__main__":
    main()