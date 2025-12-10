#!/usr/bin/env python3



"""

Raspberry Pi - AI Firewall Ä°stemcisi (v3.3 - Nihai Stabil SÃ¼rÃ¼m)

Bu script:

1. Sadece Port Tarama (SYN) veya Veri TaÅŸÄ±yan (PSH/Raw) paketlerini yakalar (GÃ¼rÃ¼ltÃ¼ Azaltma).

2. Scapy'nin FlagValue hatasÄ±nÄ± gidermek iÃ§in bayraklarÄ± string'e Ã§evirir.

3. Dosya oluÅŸturma ve silme iÅŸlemlerini stabil hale getirir.

4. Her 30 saniyede bir yapay zekaya analiz iÃ§in gÃ¶nderir.

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

# DÄ°KKAT: Ã‡ift yÃ¶nlÃ¼ koruma iÃ§in her iki arayÃ¼zÃ¼ de dinlemeliyiz.

LISTEN_INTERFACES = ["eth0" , "eth1"] 



# GÃœNCEL NGROK ADRESÄ°NÄ° BURAYA GÄ°R (Colab'daki Ã§Ä±ktÄ±):

LLM_API_URL = "https://pisolitic-unclandestinely-del.ngrok-free.dev/analyze" # LÃ¼tfen burayÄ± kendi Ngrok adresinizle deÄŸiÅŸtirin.



# Analiz SÄ±klÄ±ÄŸÄ± (Saniye)

BATCH_INTERVAL_SECONDS = 30 



# Timeout sÃ¼resi (Saniye)

REQUEST_TIMEOUT_SECONDS = 60



# Log DosyasÄ±

LOG_FILE = "firewall_logs.json"



# --- Global DeÄŸiÅŸkenler ---

packet_batch = []

batch_lock = threading.Lock()

blocked_ips_cache = set()



def check_privileges():

    """Script'in root (sudo) yetkileriyle Ã§alÄ±ÅŸÄ±p Ã§alÄ±ÅŸmadÄ±ÄŸÄ±nÄ± kontrol eder."""

    if os.geteuid() != 0:

        print("âŒ HATA: Root yetkisi gerekli (sudo python3 client.py).")

        exit(1)



def save_log_to_file(ip_address, reason, action):

    """OlayÄ± JSON dosyasÄ±na kaydeder."""

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

    except:

        logs = []



    logs.insert(0, entry)

    logs = logs[:200]

    

    try:

        with open(LOG_FILE, 'w') as f:

            json.dump(logs, f, indent=4)

    except Exception as e:

        print(f"âš ï¸ Log hatasÄ±: {e}")



def block_ip(ip_address, reason):

    """Verilen IP adresini 'iptables' kullanarak engeller."""

    if ip_address in blocked_ips_cache:

        return



    print(f"ğŸš« [KARANTÄ°NA] {ip_address} engelleniyor... Sebep: {reason}")

    try:

        # INPUT: Pi'nin kendisine eriÅŸimi kes

        subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"], check=True)

        

        # FORWARD: Pi Ã¼zerinden geÃ§iÅŸi kes

        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip_address, "-j", "DROP"], check=True)

        

        blocked_ips_cache.add(ip_address)

        save_log_to_file(ip_address, reason, "BLOCKED")

        print(f"âœ… {ip_address} tam izole edildi.")

    except Exception as e:

        print(f"âŒ Iptables HatasÄ±: {e}")



def batch_sender_loop():

    """

    (Arka Plan Thread'i) Her 30 saniyede bir paketleri sunucuya gÃ¶nderir.

    Dosya iÅŸlemleri iÃ§in gÃ¼venilirlik artÄ±rÄ±ldÄ±.

    """

    pcap_filepath = "temp_bidirectional.pcap" 



    while True:

        time.sleep(BATCH_INTERVAL_SECONDS)



        batch_to_save = []

        with batch_lock:

            if not packet_batch:

                continue

            batch_to_save = packet_batch.copy()

            packet_batch.clear()



        print(f"ğŸ“¦ [{time.strftime('%H:%M:%S')}] {len(batch_to_save)} paket analiz ediliyor...")



        # Dosya Ä°ÅŸlemleri iÃ§in GÃ¼venli Blok

        try:

            # 1. Pcap oluÅŸtur (Dosya zaten varsa Ã¼zerine yazÄ±lÄ±r)

            scapy.wrpcap(pcap_filepath, batch_to_save)

            

            # 2. Sunucuya yÃ¼kle

            with open(pcap_filepath, 'rb') as f:

                files = {'pcap_file': (pcap_filepath, f, 'application/vnd.tcpdump.pcap')}

                response = requests.post(LLM_API_URL, files=files, timeout=REQUEST_TIMEOUT_SECONDS)

            

            # 3. YanÄ±tÄ± Ä°ÅŸle

            if response.status_code == 200:

                data = response.json()

                ips = data.get('blocked_ips', [])

                reason = data.get('reason', 'AI Detection')



                if ips:

                    print(f"ğŸš¨ TEHDÄ°T TESPÄ°T EDÄ°LDÄ°! Engellenenler: {ips}")

                    for ip in ips:

                        block_ip(ip, reason)

                else:

                    print(f"âœ… AÄŸ GÃ¼venli. (AI: {reason})")

            else:

                print(f"âš ï¸ Sunucu HatasÄ±: {response.status_code}")



        except requests.exceptions.Timeout:

            print(f"â³ Zaman AÅŸÄ±mÄ±: Sunucu {REQUEST_TIMEOUT_SECONDS} saniye iÃ§inde yanÄ±t vermedi.")

        except Exception as e:

            print(f"âŒ Hata (GÃ¶nderim/Ä°ÅŸlem): {e}")



        finally:

            # DosyayÄ± sadece VARSA sil (Hata almamak iÃ§in kritik)

            if os.path.exists(pcap_filepath):

                try:

                    os.remove(pcap_filepath)

                except OSError as e:

                    print(f"âŒ DOSYA SÄ°LME HATASI: {pcap_filepath} silinemedi: {e}")



def packet_sniffer(packet):

    """

    GÃœÃ‡LENDÄ°RÄ°LMÄ°Å FÄ°LTRE: Sadece Port Tarama (SYN) veya Veri (PSH/Raw) paketlerini yakalar.

    FlagValue hatasÄ± Ã§Ã¶zÃ¼ldÃ¼.

    """

    if not packet.haslayer(scapy.IP): return

    if not packet.haslayer(scapy.TCP): return

    

    src_ip = packet[scapy.IP].src

    

    # Kendi kendine konuÅŸma (Loopback) ve zaten engellenen IP'leri atla

    if src_ip.startswith("127."): return

    if src_ip in blocked_ips_cache: return



    # --- KRÄ°TÄ°K DÃœZELTME BURADA ---

    # TCP bayraklarÄ±nÄ± string'e Ã§evirerek FlagValue hatasÄ±nÄ± Ã¶nle

    tcp_flags_str = str(packet[scapy.TCP].flags) 



    # 1. Port Tarama KontrolÃ¼ (Sadece SYN bayraÄŸÄ±)

    is_syn = 'S' in tcp_flags_str and len(tcp_flags_str) < 3 



    # 2. Veri KontrolÃ¼ (PSH bayraÄŸÄ± VEYA Raw katmanÄ± varlÄ±ÄŸÄ±)

    has_payload = 'P' in tcp_flags_str or packet.haslayer(scapy.Raw)



    # Sadece Port Tarama (is_syn) VEYA Veri TaÅŸÄ±ma (has_payload) paketlerini topla.

    if is_syn or has_payload:

        with batch_lock:

            packet_batch.append(packet)

            

            # Debug mesajÄ± (Paket akÄ±ÅŸÄ±nÄ± gÃ¶rmek iÃ§in)

            if len(packet_batch) % 50 == 0:

                 print(f"ğŸ‘€ AnlÄ±k Paket SayÄ±sÄ±: {len(packet_batch)} (Son {src_ip}) - Flags: {tcp_flags_str}")





def main():

    check_privileges()

    print(f"--- ğŸ›¡ï¸ AI FIREWALL (v3.3 - Nihai Stabil) ---")

    print(f"ğŸ“¡ Dinlenen ArayÃ¼zler: {LISTEN_INTERFACES}")

    print(f"ğŸ§  Hedef AI: {LLM_API_URL}")

    print(f"â±ï¸ Analiz AralÄ±ÄŸÄ±: {BATCH_INTERVAL_SECONDS} saniye.")

    print("--------------------------------------------------")

    print("ğŸ’¡ Not: GÃ¼rÃ¼ltÃ¼yÃ¼ kesmek iÃ§in sadece SYN, PSH/Raw paketleri toplanÄ±r.")

    print("--------------------------------------------------")



    # GÃ¶nderici thread'i baÅŸlat

    sender_thread = threading.Thread(target=batch_sender_loop, daemon=True)

    sender_thread.start()



    try:

        # Sniff: TÃ¼m TCP trafiÄŸini dinle. Python iÃ§inde filtreleme yapÄ±lÄ±yor.

        scapy.sniff(

            iface=LISTEN_INTERFACES, 

            prn=packet_sniffer,

            filter="tcp", 

            store=False

        )

    except KeyboardInterrupt:

        print("\nğŸ‘‹ KapatÄ±lÄ±yor...")

    except Exception as e:

        print(f"\nâŒ ArayÃ¼z HatasÄ±: {e}")



if __name__ == "__main__":

    main()

