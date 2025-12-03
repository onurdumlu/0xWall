import streamlit as st
import pandas as pd
import json
import time
import subprocess
import os
import hashlib
import psutil
import socket
from datetime import datetime

# ==============================================================================
# 1. AYARLAR VE VERİ YAPILARI
# ==============================================================================
st.set_page_config(page_title="Ultra-Firewall Yönetim Paneli", page_icon="🛡️", layout="wide")

FIREWALL_LOG_FILE = "firewall_logs.json"
ADMIN_AUDIT_FILE = "admin_audit.log"
USERS_DB_FILE = "auth_users.json"
WHITELIST_FILE = "whitelist.json"
DOMAIN_RULES_FILE = "domain_rules.json"

# Session State
if 'logged_in' not in st.session_state: st.session_state['logged_in'] = False
if 'username' not in st.session_state: st.session_state['username'] = None
if 'permissions' not in st.session_state: st.session_state['permissions'] = []
# Terminal çıktılarını hafızada tutmak için
if 'terminal_output' not in st.session_state: st.session_state['terminal_output'] = ""

# ==============================================================================
# 2. YARDIMCI FONKSİYONLAR
# ==============================================================================

def get_system_stats():
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    temp = 0
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            temp = int(f.read()) / 1000.0
    except: temp = 0
    return cpu, ram, disk, temp

def load_json(file_path):
    if not os.path.exists(file_path): return [] if "list" in file_path or "rules" in file_path else {}
    try:
        with open(file_path, 'r') as f: return json.load(f)
    except: return [] if "list" in file_path or "rules" in file_path else {}

def save_json(file_path, data):
    with open(file_path, 'w') as f: json.dump(data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_login(u, p):
    users = load_json(USERS_DB_FILE)
    if not users: 
        # İlk kurulum: Admin'e 'terminal' yetkisi de verelim
        users = {"admin": {"password": hash_password("123456"), "permissions": ["all", "terminal"]}}
        save_json(USERS_DB_FILE, users)
    
    if u in users and users[u]["password"] == hash_password(p):
        return True, users[u]["permissions"]
    return False, []

def has_permission(p):
    perms = st.session_state['permissions']
    return "all" in perms or p in perms

def log_audit(action, details):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = st.session_state['username'] or "SYSTEM"
    with open(ADMIN_AUDIT_FILE, "a") as f:
        f.write(f"[{ts}] [USER:{user}] [ACTION:{action}] -> {details}\n")

# ==============================================================================
# 3. FIREWALL & TERMİNAL FONKSİYONLARI
# ==============================================================================

def execute_terminal_command(command):
    """Web Terminalinden gelen komutu çalıştırır"""
    # Güvenlik için bazı çok tehlikeli veya interaktif komutları engelleyebiliriz
    forbidden = ["nano", "vim", "top", "htop", "vi", "man", "less", "more"]
    cmd_base = command.split()[0] if command else ""
    
    if cmd_base in forbidden:
        return f"HATA: '{cmd_base}' gibi interaktif komutlar web terminalinde çalıştırılamaz."

    try:
        # Komutu çalıştır (stderr'i stdout'a yönlendir)
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout
        if result.stderr:
            output += "\n[STDERR]\n" + result.stderr
        
        log_audit("TERMINAL_EXEC", f"Komut çalıştırıldı: {command}")
        return output
    except subprocess.TimeoutExpired:
        return "HATA: Komut zaman aşımına uğradı (10sn)."
    except Exception as e:
        return f"HATA: {str(e)}"

def lockdown_ssh():
    """Port 22'yi kapatır (Sadece Panel erişimi kalır)"""
    try:
        # SSH portunu kapat (INPUT zincirine kural ekle)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=True)
        log_audit("LOCKDOWN", "SSH (Port 22) erişimi kapatıldı.")
        return True, "SSH erişimi başarıyla kapatıldı. Artık sadece panelden yönetebilirsiniz."
    except Exception as e:
        return False, str(e)

def unlock_ssh():
    """Port 22'yi tekrar açar"""
    try:
        # Kuralı sil
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=True)
        log_audit("UNLOCK_SSH", "SSH erişimi tekrar açıldı.")
        return True, "SSH erişimi açıldı."
    except Exception as e:
        return False, str(e)

# (Eski fonksiyonlar aynen duruyor)
def get_real_blocked_ips():
    try:
        res = subprocess.run(["sudo", "iptables", "-S", "FORWARD"], capture_output=True, text=True)
        ips = []
        for line in res.stdout.splitlines():
            if "-j DROP" in line and "-s" in line and "-d" not in line:
                parts = line.split()
                if "-s" in parts: ips.append(parts[parts.index("-s")+1].replace("/32",""))
        return list(set(ips))
    except: return []

def manual_block_attacker(ip):
    wl = load_json(WHITELIST_FILE)
    if ip in wl: return False, "Beyaz listede!"
    try:
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"], check=True)
        log_audit("BLOCK_ATTACKER", f"Saldırgan {ip} engellendi.")
        return True, "OK"
    except Exception as e: return False, str(e)

def manual_unblock_attacker(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        log_audit("UNBLOCK_ATTACKER", f"Saldırgan {ip} açıldı.")
        return True, "OK"
    except Exception as e: return False, str(e)

def block_domain(domain):
    try:
        ips = set()
        for info in socket.getaddrinfo(domain, None, socket.AF_INET): ips.add(info[4][0])
        if not ips: return False, "IP çözülemedi."
        for ip in ips: subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
        rules = load_json(DOMAIN_RULES_FILE)
        rules_dict = {r["domain"]: r for r in rules}
        rules_dict[domain] = {"domain": domain, "blocked_ips": list(ips), "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "added_by": st.session_state['username']}
        save_json(DOMAIN_RULES_FILE, list(rules_dict.values()))
        log_audit("BLOCK_DOMAIN", f"{domain} engellendi.")
        return True, f"{len(ips)} IP engellendi."
    except Exception as e: return False, str(e)

def unblock_domain(domain):
    rules = load_json(DOMAIN_RULES_FILE)
    target = next((r for r in rules if r["domain"] == domain), None)
    if not target: return False, "Yok."
    for ip in target["blocked_ips"]: subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    new_rules = [r for r in rules if r["domain"] != domain]
    save_json(DOMAIN_RULES_FILE, new_rules)
    log_audit("UNBLOCK_DOMAIN", f"{domain} açıldı.")
    return True, "Açıldı."

# ==============================================================================
# 4. GİRİŞ EKRANI
# ==============================================================================
def login_screen():
    st.markdown("## 🛡️ Firewall Admin Girişi")
    c1,c2,c3 = st.columns([1,2,1])
    with c2:
        u = st.text_input("Kullanıcı Adı")
        p = st.text_input("Şifre", type="password")
        if st.button("Giriş", type="primary"):
            ok, perms = check_login(u, p)
            if ok:
                st.session_state.update({'logged_in':True, 'username':u, 'permissions':perms})
                log_audit("LOGIN", "Giriş yapıldı.")
                st.rerun()
            else: st.error("Hatalı!")

# ==============================================================================
# 5. ANA PANEL
# ==============================================================================
def main_app():
    c1, c2 = st.columns([8, 1])
    with c1: st.title("🛡️ Güvenlik ve Erişim Kontrol Paneli")
    with c2: 
        if st.button("Çıkış"):
            st.session_state['logged_in'] = False
            st.rerun()
    st.caption(f"Yönetici: {st.session_state['username']}")
    st.divider()

    tabs = st.tabs(["🖥️ Özet", "💻 Web Terminal (CMD)", "⛔ Gelen Tehditler", "🌐 Site Engelleme", "👥 Kullanıcılar"])

    # --- TAB 1: ÖZET ---
    with tabs[0]:
        cpu, ram, disk, temp = get_system_stats()
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("CPU", f"%{cpu}")
        k2.metric("RAM", f"%{ram}")
        k3.metric("Disk", f"%{disk}")
        k4.metric("Isı", f"{temp}°C")
        
        st.markdown("---")
        
        # LOCKDOWN MODU (SSH KAPATMA)
        st.subheader("🔒 Erişim Güvenliği (Lockdown)")
        st.info("Eğer 'Panel Harici Erişimi Kapat' derseniz, SSH (Port 22) bağlantısı kesilir. Sadece bu web paneli çalışır.")
        
        col_lock, col_unlock = st.columns(2)
        with col_lock:
            if st.button("🔒 PANEL HARİCİ ERİŞİMİ KAPAT (SSH DROP)", type="primary"):
                if has_permission("all"):
                    ok, msg = lockdown_ssh()
                    if ok: st.success(msg)
                    else: st.error(msg)
                else: st.error("Yetkiniz yok.")
        
        with col_unlock:
            if st.button("🔓 SSH ERİŞİMİNİ TEKRAR AÇ"):
                if has_permission("all"):
                    ok, msg = unlock_ssh()
                    if ok: st.success(msg)
                    else: st.error(msg)
                else: st.error("Yetkiniz yok.")

    # --- TAB 2: WEB TERMINAL (YENİ) ---
    with tabs[1]:
        st.subheader("💻 Raspberry Pi Komut İstemi (Web Terminal)")
        
        if has_permission("terminal") or has_permission("all"):
            st.warning("⚠️ DİKKAT: Burada çalıştırılan komutlar 'root' yetkisiyle çalışır. Yanlış komut sistemi bozabilir.")
            
            # Komut Girişi
            with st.form("terminal_form"):
                cmd_input = st.text_input("Komut (Örn: ls -la, ifconfig, cat /etc/hostname)", placeholder="Komutunuzu buraya yazın...")
                submitted = st.form_submit_button("Çalıştır")
                
                if submitted and cmd_input:
                    output = execute_terminal_command(cmd_input)
                    # Çıktıyı session state'e ekle (log gibi biriksin)
                    st.session_state['terminal_output'] = f"$ {cmd_input}\n{output}\n" + "-"*50 + "\n" + st.session_state['terminal_output']
                    st.rerun()

            # Terminal Ekranı (Siyah Arkaplan)
            st.markdown("### Terminal Çıktısı")
            st.code(st.session_state['terminal_output'], language="bash")
            
            if st.button("Ekranı Temizle"):
                st.session_state['terminal_output'] = ""
                st.rerun()
        else:
            st.error("⛔ Bu alana erişim yetkiniz yok.")

    # --- TAB 3: SALDIRGAN YÖNETİMİ ---
    with tabs[2]:
        c_in_1, c_in_2 = st.columns(2)
        with c_in_1:
            ip_in = st.text_input("Saldırgan IP Engelle")
            if st.button("Engelle"):
                if has_permission("block_ip"):
                    ok, msg = manual_block_attacker(ip_in)
                    if ok: st.success(msg)
                    else: st.error(msg)
        with c_in_2:
            current_attackers = get_real_blocked_ips()
            if current_attackers:
                sel = st.selectbox("Engeli Kaldır", current_attackers)
                if st.button("Kaldır"):
                    if has_permission("unblock_ip"): manual_unblock_attacker(sel)

    # --- TAB 4: SİTE ENGELLEME ---
    with tabs[3]:
        dom = st.text_input("Engellenecek Site (Örn: youtube.com)")
        if st.button("Siteyi Engelle"):
            if has_permission("block_ip"):
                ok, msg = block_domain(dom)
                if ok: st.success(msg)
                else: st.error(msg)
        
        st.markdown("#### Yasaklı Siteler")
        rules = load_json(DOMAIN_RULES_FILE)
        if rules:
            st.dataframe(pd.DataFrame(rules)[["domain", "date", "added_by"]], use_container_width=True)
            d_del = st.selectbox("Yasağı Kaldır", [r["domain"] for r in rules])
            if st.button("Yasağı Kaldır"):
                if has_permission("unblock_ip"): 
                    unblock_domain(d_del)
                    st.rerun()

    # --- TAB 5: KULLANICILAR ---
    with tabs[4]:
        if has_permission("all"):
            st.subheader("Kullanıcı Yönetimi")
            users = load_json(USERS_DB_FILE)
            with st.form("add_usr"):
                nu = st.text_input("Kullanıcı Adı")
                np = st.text_input("Şifre", type="password")
                term_perm = st.checkbox("Terminal Erişim Yetkisi Ver")
                if st.form_submit_button("Ekle"):
                    if nu not in users:
                        perms = ["view_logs"]
                        if term_perm: perms.append("terminal")
                        users[nu] = {"password": hash_password(np), "permissions": perms}
                        save_json(USERS_DB_FILE, users)
                        st.success("Eklendi")
                        st.rerun()
            st.write(users)

if st.session_state['logged_in']: main_app()
else: login_screen()