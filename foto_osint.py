from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
import webbrowser

def get_exif_data(img_path):
    try:
        image = Image.open(img_path)
        info = image._getexif()
        if not info:
            return None
        exif_data = {}
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)
            exif_data[decoded] = value
        return exif_data
    except Exception as e:
        print(f"Hata: {e}")
        return None

def get_gps_info(exif_data):
    if not exif_data or "GPSInfo" not in exif_data:
        return None
    gps_info = {}
    for key in exif_data["GPSInfo"]:
        decoded = GPSTAGS.get(key, key)
        gps_info[decoded] = exif_data["GPSInfo"][key]
    return gps_info

def convert_to_degrees(value):
    d = value[0][0] / value[0][1]
    m = value[1][0] / value[1][1]
    s = value[2][0] / value[2][1]
    return d + (m / 60.0) + (s / 3600.0)

def get_gps_coordinates(gps_info):
    if not gps_info:
        return None
    lat = convert_to_degrees(gps_info['GPSLatitude'])
    if gps_info['GPSLatitudeRef'] == 'S':
        lat = -lat
    lon = convert_to_degrees(gps_info['GPSLongitude'])
    if gps_info['GPSLongitudeRef'] == 'W':
        lon = -lon
    return lat, lon

def open_google_reverse_image_search(img_path):
    print("\n🔎 EXIF verisi yok veya GPS bilgisi bulunamadı. Tersine görsel arama başlatılıyor...")
    query_url = f"https://images.google.com/searchbyimage?image_url=file://{os.path.abspath(img_path)}"
    print(f"Google Tersine Görsel Arama linki:\n{query_url}")
    try:
        webbrowser.open(query_url)
    except:
        print("Tarayıcı açılamadı, linki elle açabilirsin.")

def main():
    img_path = input("Fotoğraf dosya yolunu gir (örn: /home/salih/foto.jpg): ").strip()

    if not os.path.isfile(img_path):
        print("❌ Dosya bulunamadı.")
        return

    exif_data = get_exif_data(img_path)
    if exif_data:
        print("\n📸 EXIF Bilgileri:")
        for key, val in exif_data.items():
            print(f"{key}: {val}")

        gps_info = get_gps_info(exif_data)
        coords = get_gps_coordinates(gps_info)

        if coords:
            print(f"\n🗺️ GPS Koordinatları: {coords}")
            print(f"🌐 Google Maps linki: https://www.google.com/maps?q={coords[0]},{coords[1]}")
        else:
            open_google_reverse_image_search(img_path)
    else:
        open_google_reverse_image_search(img_path)

if __name__ == "__main__":
    main()
