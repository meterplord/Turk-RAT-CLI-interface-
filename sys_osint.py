import requests
import sys

def check_username(username, use_tor=False):
    platforms = {
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://www.instagram.com/{username}/',
        'Facebook': f'https://www.facebook.com/{username}',
        'LinkedIn': f'https://www.linkedin.com/in/{username}',
        'GitHub': f'https://github.com/{username}',
        'Reddit': f'https://www.reddit.com/user/{username}',
        'TikTok': f'https://www.tiktok.com/@{username}',
        'Snapchat': f'https://www.snapchat.com/add/{username}',
        'Pinterest': f'https://www.pinterest.com/{username}/',
        'YouTube': f'https://www.youtube.com/@{username}',
        'Twitch': f'https://www.twitch.tv/{username}',
        'Discord': f'https://discord.com/users/{username}',
        'Telegram': f'https://t.me/{username}',
        'Spotify': f'https://open.spotify.com/user/{username}',
        'Medium': f'https://medium.com/@{username}',
        'Quora': f'https://www.quora.com/profile/{username}',
        'Flickr': f'https://www.flickr.com/people/{username}/',
        'Vimeo': f'https://vimeo.com/{username}',
        'SoundCloud': f'https://soundcloud.com/{username}',
        'DeviantArt': f'https://www.deviantart.com/{username}',
        'Behance': f'https://www.behance.net/{username}',
        'Dribbble': f'https://dribbble.com/{username}',
        'Patreon': f'https://www.patreon.com/{username}',
        'Tumblr': f'https://{username}.tumblr.com'
    }
    valid_links = []
    proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'} if use_tor else {}
    for platform, url in platforms.items():
        try:
            response = requests.get(url, proxies=proxies, timeout=10)
            status = response.status_code
            content = response.text.lower()
            if status == 200 and "not found" not in content and "error" not in content:
                valid_links.append(f"{platform}: {url}")
        except requests.RequestException:
            continue

    if valid_links:
        print("Geçerli Linkler:")
        for link in valid_links:
            print(link)
    else:
        print("Kullanıcı bulunamadı.")
    return valid_links

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sys-osint.py <username> [--tor]")
        sys.exit(1)
    username = sys.argv[1]
    use_tor = "--tor" in sys.argv
    check_username(username, use_tor)
