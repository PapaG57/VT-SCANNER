"""
================================================================================
PROJET : VT-SCANNER
AUTEUR : FG Developpement & Gemini (IA)
SITE WEB : https://www.fgdeveloppement.com
DATE : 27 Mai 2026
VERSION : 1.0.0
DESCRIPTION : Surveillance automatique du dossier Téléchargements avec analyse
              VirusTotal et mise en quarantaine des menaces.
================================================================================
"""

import os
import sys
import time
import hashlib
import requests
import threading
import webbrowser
import psutil
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from plyer import notification
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw

# --- CONFIGURATION & INFOS ---
VERSION = "1.2.0"
AUTHOR = "FG Developpement"
PROJECT_NAME = "VT-SCANNER"
WEBSITE_URL = "https://www.fgdeveloppement.com"

# Charger les variables d'environnement
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
WATCH_DIR = os.path.expanduser(os.getenv("DOWNLOADS_DIR", "~/Downloads"))
QUARANTINE_DIR = os.path.expanduser(os.getenv("QUARANTINE_DIR", "~/Downloads/Quarantine"))

# Cache pour éviter de scanner plusieurs fois la même IP
checked_ips = {}

# S'assurer que le dossier de quarantaine existe
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# Remplacer toaster par notification
def notify(title, message):
    try:
        notification.notify(
            title=title,
            message=message,
            app_name=PROJECT_NAME,
            app_icon="tray_icon.png" if os.path.exists("tray_icon.png") else None,
            timeout=5
        )
    except Exception as e:
        print(f"Erreur notification : {e}")

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(resource, resource_type="file"):
    """Vérifie un fichier ou une IP sur VirusTotal."""
    endpoint = "files" if resource_type == "file" else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{resource}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print(f"Quota atteint (4 req/min) pour {resource}.")
            return "RATE_LIMITED"
        elif response.status_code == 403:
            print("Quota journalier/mensuel épuisé.")
            return "QUOTA_EXCEEDED"
        return None
    except Exception as e:
        print(f"Erreur connexion API: {e}")
        return None

def scan_file(file_path):
    """Effectue un scan manuel d'un fichier."""
    filename = os.path.basename(file_path)
    if not os.path.exists(file_path):
        print(f"Erreur : Le fichier {file_path} n'existe pas.")
        return

    try:
        file_hash = get_file_hash(file_path)
        result = check_virustotal(file_hash, "file")

        if result == "RATE_LIMITED":
            notify("VT-SCANNER", "Limite de 4 scans/min atteinte. Réessayez dans un instant.")
            return
        
        if result:
            malicious = result['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            if malicious > 0:
                notify("🛡️ VT-SCANNER : Menace !", f"{filename} est suspect ({malicious} alertes).")
            else:
                notify("✅ VT-SCANNER : Sain", f"{filename} a été vérifié avec succès.")
        else:
            notify("❓ VT-SCANNER : Inconnu", f"{filename} n'est pas encore répertorié sur VirusTotal.")
    except Exception as e:
        print(f"Erreur lors du scan : {e}")

def is_private_ip(ip):
    """Vérifie si une IP est locale (LAN)."""
    try:
        ip_parts = list(map(int, ip.split('.')))
        if ip_parts[0] == 10: return True
        if ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31: return True
        if ip_parts[0] == 192 and ip_parts[1] == 168: return True
        if ip_parts[0] == 127: return True
        return False
    except:
        return True

def monitor_network():
    """Surveille les connexions réseau actives."""
    print("Démarrage de la surveillance réseau...")
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    # Ignorer les IP locales et celles déjà vérifiées récemment
                    if is_private_ip(remote_ip) or remote_ip in checked_ips:
                        continue
                    
                    # Vérifier sur VirusTotal
                    result = check_virustotal(remote_ip, "ip")
                    
                    if result == "RATE_LIMITED":
                        time.sleep(15) # Attendre un peu avant la prochaine IP
                        continue
                    
                    if result and result != "QUOTA_EXCEEDED":
                        stats = result['data']['attributes']['last_analysis_stats']
                        malicious = stats.get('malicious', 0)
                        checked_ips[remote_ip] = malicious
                        
                        if malicious > 0:
                            process_name = "Inconnu"
                            try:
                                process_name = psutil.Process(conn.pid).name()
                            except: pass
                            notify("⚠️ Connexion Suspecte !", f"IP: {remote_ip}\nProcessus: {process_name}\nAlertes: {malicious}")
                    else:
                        checked_ips[remote_ip] = 0 # Marquer comme neutre si inconnu
                        
                time.sleep(0.5) # Petite pause entre chaque connexion pour ne pas saturer le CPU
        except Exception as e:
            print(f"Erreur monitoring réseau: {e}")
        
        time.sleep(60) # Scan complet toutes les minutes

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory: return
        file_path = event.src_path
        filename = os.path.basename(file_path)

        if filename.endswith((".crdownload", ".tmp", ".part")): return

        time.sleep(2) # Attendre la fin de l'écriture

        try:
            file_hash = get_file_hash(file_path)
            result = check_virustotal(file_hash, "file")

            if result == "RATE_LIMITED":
                return

            if result and result != "QUOTA_EXCEEDED":
                malicious = result['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                if malicious > 0:
                    dest_path = os.path.join(QUARANTINE_DIR, filename)
                    os.rename(file_path, dest_path)
                    notify("🛡️ VT-SCANNER : Menace !", f"{filename} déplacé en quarantaine ({malicious} alertes).")
                else:
                    notify("✅ VT-SCANNER : Sain", f"{filename} a été vérifié avec succès.")
            elif result != "QUOTA_EXCEEDED":
                notify("❓ VT-SCANNER : Inconnu", f"{filename} n'est pas encore répertorié sur VirusTotal.")
        except Exception as e:
            print(f"Erreur scan : {e}")


# --- SYSTEM TRAY ICON ---
def get_icon_image():
    """Charge le logo personnalisé pour le systray."""
    try:
        # Essayer de charger le logo que nous avons copié
        return Image.open("tray_icon.png")
    except Exception as e:
        print(f"Erreur chargement icone : {e}")
        # Repli sur une icône générée si le fichier est absent
        width, height = 64, 64
        image = Image.new('RGB', (width, height), (30, 30, 30))
        dc = ImageDraw.Draw(image)
        dc.rectangle([10, 10, 54, 54], fill=(0, 120, 215))
        return image

def on_exit(icon, item):
    icon.stop()
    # Forcer l'arrêt pour fermer tous les threads
    os._exit(0)

def open_website(icon, item):
    webbrowser.open(WEBSITE_URL)

def run_tray():
    menu = Menu(
        MenuItem(f"{PROJECT_NAME} v{VERSION}", None, enabled=False),
        MenuItem(f"Par {AUTHOR}", None, enabled=False),
        MenuItem("Site Web", open_website),
        MenuItem("---", None, enabled=False),
        MenuItem("Quitter", on_exit)
    )
    icon = Icon("VT-Scanner", get_icon_image(), f"{PROJECT_NAME} - Actif", menu)
    icon.run()

# --- MAIN ---
if __name__ == "__main__":
    print("Vérification de la clé API...")
    if not API_KEY or API_KEY == "votre_cle_api_ici":
        notify("Erreur VT-SCANNER", "Veuillez configurer votre clé API dans le fichier .env")
        sys.exit(1)

    print(f"Initialisation de {PROJECT_NAME} v{VERSION}...")
    
    # 1. Lancer le watcher de fichiers
    print("Lancement du moniteur de fichiers...")
    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    # 2. Lancer le monitoring réseau dans un thread séparé
    print("Lancement du thread réseau...")
    net_thread = threading.Thread(target=monitor_network, daemon=True)
    net_thread.start()

    print(f"Démarrage de l'icône systray...")
    try:
        # 3. Lancer l'icône de la barre des tâches (bloquant)
        run_tray()
    except Exception as e:
        print(f"ERREUR FATALE Systray : {e}")
    finally:
        print("Arrêt des services...")
        observer.stop()
        observer.join()
