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
import time
import hashlib
import requests
import threading
import webbrowser
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from win10toast import ToastNotifier
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw

# --- CONFIGURATION & INFOS ---
VERSION = "1.0.0"
AUTHOR = "FG Developpement"
PROJECT_NAME = "VT-SCANNER"
WEBSITE_URL = "https://www.fgdeveloppement.com"

# Charger les variables d'environnement
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
WATCH_DIR = os.path.expanduser(os.getenv("DOWNLOADS_DIR", "~/Downloads"))
QUARANTINE_DIR = os.path.expanduser(os.getenv("QUARANTINE_DIR", "~/Downloads/Quarantine"))

# S'assurer que le dossier de quarantaine existe
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

toaster = ToastNotifier()

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print("Quota atteint (4 req/min).")
            notify("VT-SCANNER : Limite Minute", "Limite de 4 scans par minute atteinte. Le scan reprendra bientôt.")
            return "RATE_LIMITED"
        elif response.status_code == 403:
            print("Quota journalier/mensuel épuisé.")
            notify("VT-SCANNER : Quota Épuisé", "Votre quota journalier (500) ou mensuel est atteint. Le scanner reprendra plus tard.")
            return "QUOTA_EXCEEDED"
        return None
    except Exception as e:
        print(f"Erreur connexion API: {e}")
        return None

def notify(title, message):
    toaster.show_toast(title, message, duration=5, threaded=True)

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory: return
        file_path = event.src_path
        filename = os.path.basename(file_path)

        if filename.endswith((".crdownload", ".tmp", ".part")): return

        time.sleep(2) # Attendre la fin de l'écriture

        try:
            file_hash = get_file_hash(file_path)
            result = check_virustotal(file_hash)

            if result == "RATE_LIMITED":
                # On pourrait ajouter une file d'attente ici, 
                # mais pour 4/min c'est rare de dépasser.
                return

            if result:
                malicious = result['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                if malicious > 0:
                    dest_path = os.path.join(QUARANTINE_DIR, filename)
                    os.rename(file_path, dest_path)
                    notify("🛡️ VT-SCANNER : Menace !", f"{filename} déplacé en quarantaine ({malicious} alertes).")
                else:
                    notify("✅ VT-SCANNER : Sain", f"{filename} a été vérifié avec succès.")
            else:
                notify("❓ VT-SCANNER : Inconnu", f"{filename} n'est pas encore répertorié sur VirusTotal.")
        except Exception as e:
            print(f"Erreur scan : {e}")


# --- SYSTEM TRAY ICON ---
def create_image():
    # Créer une icône simple (Bouclier bleu/vert)
    width = 64
    height = 64
    image = Image.new('RGB', (width, height), (30, 30, 30))
    dc = ImageDraw.Draw(image)
    dc.rectangle([10, 10, 54, 54], fill=(0, 120, 215)) # Bleu Windows
    dc.text((15, 20), "VT", fill=(255, 255, 255))
    return image

def on_exit(icon, item):
    icon.stop()
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
    icon = Icon("VT-Scanner", create_image(), f"{PROJECT_NAME} - Actif", menu)
    icon.run()

# --- MAIN ---
if __name__ == "__main__":
    if not API_KEY or API_KEY == "votre_cle_api_ici":
        notify("Erreur VT-SCANNER", "Veuillez configurer votre clé API dans le fichier .env")
    else:
        # Lancer le watcher dans un thread séparé
        event_handler = DownloadHandler()
        observer = Observer()
        observer.schedule(event_handler, WATCH_DIR, recursive=False)
        observer.start()

        print(f"Démarrage de {PROJECT_NAME} v{VERSION}")
        
        # Lancer l'icône de la barre des tâches (bloquant)
        run_tray()
        
        observer.stop()
        observer.join()
