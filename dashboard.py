import streamlit as st

import pandas as pd

import json

import subprocess

import os

import hashlib

import psutil

import socket

from datetime import datetime



# ==============================================================================

# 1. AYARLAR VE VERÄ° YAPILARI

# ==============================================================================

st.set_page_config(page_title="Ultra-Firewall YÃ¶netim Paneli", page_icon="ğŸ›¡ï¸", layout="wide")



FIREWALL_LOG_FILE = "firewall_logs.json"

ADMIN_AUDIT_FILE = "admin_audit.log"

USERS_DB_FILE = "auth_users.json"

WHITELIST_FILE = "whitelist.json"

DOMAIN_RULES_FILE = "domain_rules.json"



# Session State BaÅŸlatma

if 'logged_in' not in st.session_state: st.session_state['logged_in'] = False

if 'username' not in st.session_state: st.session_state['username'] = None

if 'permissions' not in st.session_state: st.session_state['permissions'] = []

if 'terminal_output' not in st.session_state: st.session_state['terminal_output'] = ""



# ==============================================================================

# 2. YARDIMCI FONKSÄ°YONLAR

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

# 3. FIREWALL, SSH & VNC YÃ–NETÄ°MÄ°

# ==============================================================================



def execute_terminal_command(command):

    forbidden = ["nano", "vim", "top", "htop", "vi", "man", "less", "more"]

    cmd_base = command.split()[0] if command else ""

    if cmd_base in forbidden:

        return f"HATA: '{cmd_base}' gibi interaktif komutlar web terminalinde Ã§alÄ±ÅŸtÄ±rÄ±lamaz."

    try:

        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)

        output = result.stdout

        if result.stderr: output += "\n[STDERR]\n" + result.stderr

        log_audit("TERMINAL_EXEC", f"Komut: {command}")

        return output

    except Exception as e: return f"HATA: {str(e)}"



# --- SSH YÃ–NETÄ°MÄ° ---

def lockdown_ssh():

    try:

        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=True)

        log_audit("LOCKDOWN_SSH", "SSH (Port 22) kapatÄ±ldÄ±.")

        return True, "SSH eriÅŸimi kapatÄ±ldÄ±."

    except Exception as e: return False, str(e)



def unlock_ssh():

    try:

        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=True)

        log_audit("UNLOCK_SSH", "SSH eriÅŸimi aÃ§Ä±ldÄ±.")

        return True, "SSH eriÅŸimi aÃ§Ä±ldÄ±."

    except Exception as e: return False, str(e)



# --- VNC YÃ–NETÄ°MÄ° ---

def lockdown_vnc():

    try:

        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "5900", "-j", "DROP"], check=True)

        log_audit("LOCKDOWN_VNC", "VNC (Port 5900) kapatÄ±ldÄ±.")

        return True, "VNC ekran paylaÅŸÄ±mÄ± kapatÄ±ldÄ±."

    except Exception as e: return False, str(e)



def unlock_vnc():

    try:

        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "5900", "-j", "DROP"], check=True)

        log_audit("UNLOCK_VNC", "VNC eriÅŸimi aÃ§Ä±ldÄ±.")

        return True, "VNC eriÅŸimi aÃ§Ä±ldÄ±."

    except Exception as e: return False, str(e)



# --- SALDIRGAN ENGELLEME ---

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

        log_audit("BLOCK_ATTACKER", f"SaldÄ±rgan {ip} engellendi.")

        return True, "OK"

    except Exception as e: return False, str(e)



def manual_unblock_attacker(ip):

    try:

        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=True)

        log_audit("UNBLOCK_ATTACKER", f"SaldÄ±rgan {ip} aÃ§Ä±ldÄ±.")

        return True, "OK"

    except Exception as e: return False, str(e)



# --- GELÄ°ÅMÄ°Å DOMAIN ENGELLEME (STRING MATCHING + IP) ---

def block_domain(domain):

    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "").strip()

    domain = domain.split('/')[0] 

    

    if not domain: return False, "GeÃ§ersiz domain."



    try:

        # String Matching (Paket Ä°Ã§eriÄŸi)

        chains = ["OUTPUT", "FORWARD"]

        for chain in chains:

            check = subprocess.run(

                ["sudo", "iptables", "-C", chain, "-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP"],

                stderr=subprocess.DEVNULL

            )

            if check.returncode != 0:

                subprocess.run(

                    ["sudo", "iptables", "-I", chain, "1", "-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP"],

                    check=True

                )



        # IP BazlÄ± (Yedek)

        ips = set()

        try:

            for info in socket.getaddrinfo(domain, None, socket.AF_INET): ips.add(info[4][0])

            for info in socket.getaddrinfo(f"www.{domain}", None, socket.AF_INET): ips.add(info[4][0])

        except: pass 



        for ip in ips:

            for chain in chains:

                check_ip = subprocess.run(

                    ["sudo", "iptables", "-C", chain, "-d", ip, "-j", "DROP"],

                    stderr=subprocess.DEVNULL

                )

                if check_ip.returncode != 0:

                     subprocess.run(["sudo", "iptables", "-I", chain, "1", "-d", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)



        # JSON KayÄ±t

        rules = load_json(DOMAIN_RULES_FILE)

        rules = [r for r in rules if r["domain"] != domain]

        

        new_rule = {

            "domain": domain,

            "blocked_ips": list(ips),

            "method": "String Match + IP",

            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "added_by": st.session_state.get('username', 'system')

        }

        rules.append(new_rule)

        save_json(DOMAIN_RULES_FILE, rules)



        log_audit("BLOCK_DOMAIN", f"{domain} engellendi (String Match + {len(ips)} IP).")

        return True, f"{domain} engellendi."



    except Exception as e:

        return False, f"Hata: {str(e)}"



def unblock_domain(domain):

    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "").strip()

    

    rules = load_json(DOMAIN_RULES_FILE)

    target = next((r for r in rules if r["domain"] == domain), None)

    

    if not target: return False, "Domain listede bulunamadÄ±."



    chains = ["OUTPUT", "FORWARD"]

    try:

        for chain in chains:

            subprocess.run(

                ["sudo", "iptables", "-D", chain, "-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP"],

                stderr=subprocess.DEVNULL

            )

        if "blocked_ips" in target:

            for ip in target["blocked_ips"]:

                for chain in chains:

                    subprocess.run(["sudo", "iptables", "-D", chain, "-d", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)



        new_rules = [r for r in rules if r["domain"] != domain]

        save_json(DOMAIN_RULES_FILE, new_rules)

        

        log_audit("UNBLOCK_DOMAIN", f"{domain} engeli kaldÄ±rÄ±ldÄ±.")

        return True, f"{domain} engeli kaldÄ±rÄ±ldÄ±."

    except Exception as e:

        return False, f"Hata: {str(e)}"



# ==============================================================================

# 4. GÄ°RÄ°Å EKRANI

# ==============================================================================

def login_screen():

    st.markdown("## ğŸ›¡ï¸ Firewall Admin GiriÅŸi")

    c1,c2,c3 = st.columns([1,2,1])

    with c2:

        u = st.text_input("KullanÄ±cÄ± AdÄ±")

        p = st.text_input("Åifre", type="password")

        if st.button("GiriÅŸ", type="primary"):

            ok, perms = check_login(u, p)

            if ok:

                st.session_state.update({'logged_in':True, 'username':u, 'permissions':perms})

                log_audit("LOGIN", "GiriÅŸ yapÄ±ldÄ±.")

                st.rerun()

            else: st.error("HatalÄ± KullanÄ±cÄ± AdÄ± veya Åifre!")



# ==============================================================================

# 5. ANA PANEL

# ==============================================================================

def main_app():

    c1, c2 = st.columns([8, 1])

    with c1: st.title("ğŸ›¡ï¸ GÃ¼venlik ve EriÅŸim Kontrol Paneli")

    with c2: 

        if st.button("Ã‡Ä±kÄ±ÅŸ"):

            st.session_state['logged_in'] = False

            st.rerun()

    st.caption(f"YÃ¶netici: {st.session_state['username']}")

    st.divider()



    tabs = st.tabs(["ğŸ–¥ï¸ Ã–zet", "ğŸ’» Web Terminal", "â›” Gelen Tehditler", "ğŸŒ Site Engelleme", "ğŸ‘¥ KullanÄ±cÄ±lar"])



    # --- TAB 1: Ã–ZET ---

    with tabs[0]:

        cpu, ram, disk, temp = get_system_stats()

        k1, k2, k3, k4 = st.columns(4)

        k1.metric("CPU", f"%{cpu}")

        k2.metric("RAM", f"%{ram}")

        k3.metric("Disk", f"%{disk}")

        k4.metric("IsÄ±", f"{temp}Â°C")

        

        st.markdown("---")

        st.subheader("ğŸ”’ EriÅŸim GÃ¼venliÄŸi (Lockdown)")

        

        # SSH

        st.markdown("**SSH BaÄŸlantÄ±sÄ± (Port 22)**")

        col_ssh_lock, col_ssh_unlock = st.columns(2)

        with col_ssh_lock:

            # GÃœNCELLEME: use_container_width -> width='stretch'

            if st.button("ğŸ”´ SSH KAPAT", width="stretch"):

                if has_permission("all"):

                    ok, msg = lockdown_ssh()

                    if ok: st.success(msg)

                    else: st.error(msg)

                else: st.error("Yetkisiz.")

        with col_ssh_unlock:

            if st.button("ğŸŸ¢ SSH AÃ‡", width="stretch"):

                if has_permission("all"):

                    ok, msg = unlock_ssh()

                    if ok: st.success(msg)

                    else: st.error(msg)

                else: st.error("Yetkisiz.")

        

        st.markdown("---")



        # VNC

        st.markdown("**VNC BaÄŸlantÄ±sÄ± (Port 5900)**")

        col_vnc_lock, col_vnc_unlock = st.columns(2)

        with col_vnc_lock:

            if st.button("ğŸ”´ VNC KAPAT", width="stretch"):

                if has_permission("all"):

                    ok, msg = lockdown_vnc()

                    if ok: st.success(msg)

                    else: st.error(msg)

                else: st.error("Yetkisiz.")

        with col_vnc_unlock:

            if st.button("ğŸŸ¢ VNC AÃ‡", width="stretch"):

                if has_permission("all"):

                    ok, msg = unlock_vnc()

                    if ok: st.success(msg)

                    else: st.error(msg)

                else: st.error("Yetkisiz.")



    # --- TAB 2: WEB TERMINAL ---

    with tabs[1]:

        st.subheader("ğŸ’» Web Terminal")

        if has_permission("terminal") or has_permission("all"):

            with st.form("terminal_form"):

                cmd_input = st.text_input("Komut", placeholder="ls -la")

                submitted = st.form_submit_button("Ã‡alÄ±ÅŸtÄ±r")

                if submitted and cmd_input:

                    output = execute_terminal_command(cmd_input)

                    st.session_state['terminal_output'] = f"$ {cmd_input}\n{output}\n" + "-"*50 + "\n" + st.session_state['terminal_output']

                    st.rerun()



            st.code(st.session_state['terminal_output'], language="bash")

            if st.button("EkranÄ± Temizle"):

                st.session_state['terminal_output'] = ""

                st.rerun()

        else: st.error("EriÅŸim yok.")



    # --- TAB 3: SALDIRGAN YÃ–NETÄ°MÄ° ---

    with tabs[2]:

        c_in_1, c_in_2 = st.columns(2)

        with c_in_1:

            ip_in = st.text_input("SaldÄ±rgan IP Engelle")

            if st.button("Engelle"):

                if has_permission("block_ip") or has_permission("all"):

                    ok, msg = manual_block_attacker(ip_in)

                    if ok: st.success(msg)

                    else: st.error(msg)

        with c_in_2:

            current_attackers = get_real_blocked_ips()

            if current_attackers:

                sel = st.selectbox("Engeli KaldÄ±r", current_attackers)

                if st.button("KaldÄ±r"):

                    if has_permission("unblock_ip") or has_permission("all"): manual_unblock_attacker(sel)



    # --- TAB 4: SÄ°TE ENGELLEME ---

    with tabs[3]:

        st.subheader("ğŸŒ Site Engelleme (Ä°Ã§erik Filtreleme)")

        st.info("Bu Ã¶zellik, paket iÃ§eriÄŸinde site adÄ±nÄ± arar. IP deÄŸiÅŸse bile engelleme devam eder.")

        

        dom = st.text_input("Engellenecek Site (Ã–rn: tiktok.com)")

        if st.button("Siteyi Engelle"):

            if has_permission("block_ip") or has_permission("all"):

                ok, msg = block_domain(dom)

                if ok: st.success(msg)

                else: st.error(msg)

        

        st.markdown("#### YasaklÄ± Siteler")

        rules = load_json(DOMAIN_RULES_FILE)

        

        # DÃœZELTME: KeyError ve Deprecation hatasÄ± giderildi

        if rules:

            df = pd.DataFrame(rules)

            # EÄŸer eski dosya varsa 'method' sÃ¼tunu eksik olabilir, onu tamamla:

            if "method" not in df.columns:

                df["method"] = "Legacy (Eski)"

            

            # use_container_width -> width='stretch'

            st.dataframe(df[["domain", "method", "date", "added_by"]], width="stretch")

            

            d_del = st.selectbox("YasaÄŸÄ± KaldÄ±r", [r["domain"] for r in rules])

            if st.button("YasaÄŸÄ± KaldÄ±r"):

                if has_permission("unblock_ip") or has_permission("all"): 

                    unblock_domain(d_del)

                    st.rerun()



    # --- TAB 5: KULLANICILAR ---

    with tabs[4]:

        if has_permission("all"):

            st.subheader("KullanÄ±cÄ± YÃ¶netimi")

            users = load_json(USERS_DB_FILE)

            with st.form("add_usr"):

                nu = st.text_input("KullanÄ±cÄ± AdÄ±")

                np = st.text_input("Åifre", type="password")

                term_perm = st.checkbox("Terminal EriÅŸim Yetkisi")

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

