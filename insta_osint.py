import instaloader
import sys

def get_instagram_info(username):
    loader = instaloader.Instaloader()
    try:
        profile = instaloader.Profile.from_username(loader.context, username)
        result = (
            f"Kullanıcı Adı: {profile.username}\n"
            f"Ad Soyad: {profile.full_name}\n"
            f"Takipçi Sayısı: {profile.followers}\n"
            f"Takip Edilenler: {profile.followees}\n"
            f"Gönderi Sayısı: {profile.mediacount}\n"
            f"Profil Açıklaması: {profile.biography}\n"
            f"Profil Resmi URL: {profile.profile_pic_url}\n"
            f"Profil Gizli mi?: {'Evet' if profile.is_private else 'Hayır'}\n"
            f"Doğrulanmış mı?: {'Evet' if profile.is_verified else 'Hayır'}"
        )
        print(result)
    except Exception as e:
        print("Kullanıcı bulunamadı veya hata oluştu:", str(e))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python insta_osint.py <username>")
        sys.exit(1)
    username = sys.argv[1]
    get_instagram_info(username)
