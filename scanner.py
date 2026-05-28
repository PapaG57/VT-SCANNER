"""
================================================================================
PROJET : VT-SCANNER
AUTEUR : FG Developpement & Gemini (IA)
SITE WEB : https://www.fgdeveloppement.com
DATE : 27 Mai 2026
VERSION : 1.2.1
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
import json
import ctypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from plyer import notification
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw

# --- CONFIGURATION & INFOS ---
VERSION = "1.4.4"
AUTHOR = "FG Developpement"
PROJECT_NAME = "VirusTotal Scanner"
WEBSITE_URL = "https://www.fgdeveloppement.com"
DETECTION_THRESHOLD = 3

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Déterminer le vrai dossier de l'application (où se trouve le .exe ou le script)
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PNG_ICON_PATH = resource_path("tray_icon.png")
ICO_ICON_PATH = resource_path("tray_icon.ico")
WHITELIST_PATH = os.path.join(BASE_DIR, "whitelist.json")

def log_alert(message):
    log_path = os.path.join(BASE_DIR, "alerts.log")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except: pass

# Log de démarrage immédiat pour le debug
log_alert("--- TEST DEMARRAGE APPLICATION ---")

# Charger la whitelist
def load_whitelist():
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, 'r') as f:
                return json.load(f)
        except: return {"ips": [], "files": []}
    return {"ips": [], "files": []}

def save_whitelist(whitelist):
    try:
        with open(WHITELIST_PATH, 'w') as f:
            json.dump(whitelist, f, indent=4)
    except Exception as e:
        print(f"Erreur sauvegarde whitelist : {e}")

whitelist = load_whitelist()

# Compatibilité descendante si ICON_PATH est utilisé ailleurs
ICON_PATH = PNG_ICON_PATH

def ensure_ico():
    """Convertit le PNG en ICO pour Windows si nécessaire."""
    if not os.path.exists(ICO_ICON_PATH) and os.path.exists(PNG_ICON_PATH):
        try:
            img = Image.open(PNG_ICON_PATH)
            img.save(ICO_ICON_PATH, format="ICO", sizes=[(64, 64)])
            print(f"Icône convertie : {ICO_ICON_PATH}")
        except Exception as e:
            print(f"Erreur conversion ICO : {e}")

# Charger les variables d'environnement
try:
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)
    else:
        # Tenter de charger depuis le répertoire de l'exécutable si différent
        load_dotenv(os.path.join(os.path.dirname(sys.executable), ".env"))
except Exception as e:
    log_alert(f"Erreur chargement .env : {e}")

API_KEY = os.getenv("VT_API_KEY")
WATCH_DIR = os.path.expanduser(os.getenv("DOWNLOADS_DIR", "~/Downloads"))
QUARANTINE_DIR = os.path.expanduser(os.getenv("QUARANTINE_DIR", "~/Downloads/Quarantine"))

# Cache pour éviter de scanner plusieurs fois la même IP
checked_ips = {}
last_alert_ip = None
last_alert_proc = None

def add_to_whitelist_ip(icon, item):
    global last_alert_ip
    if last_alert_ip:
        wl = load_whitelist()
        if "ips" not in wl: wl["ips"] = []
        if last_alert_ip not in wl["ips"]:
            wl["ips"].append(last_alert_ip)
            save_whitelist(wl)
            global whitelist
            whitelist = wl
            notify("VT-SCANNER", f"IP {last_alert_ip} ajoutée à la whitelist.")
            last_alert_ip = None

def add_to_whitelist_proc(icon, item):
    global last_alert_proc
    if last_alert_proc:
        wl = load_whitelist()
        if "processes" not in wl: wl["processes"] = []
        if last_alert_proc not in wl["processes"]:
            wl["processes"].append(last_alert_proc)
            save_whitelist(wl)
            global whitelist
            whitelist = wl
            notify("VT-SCANNER", f"Processus {last_alert_proc} ajouté aux exclusions.")
            last_alert_proc = None

def open_whitelist_file(icon, item):
    import subprocess
    subprocess.Popen(["notepad.exe", WHITELIST_PATH])

def open_logs(icon, item):
    log_path = os.path.join(BASE_DIR, "alerts.log")
    if not os.path.exists(log_path):
        with open(log_path, "w") as f: f.write("--- LOGS ALERTES VT-SCANNER ---\n")
    import subprocess
    subprocess.Popen(["notepad.exe", log_path])

def log_alert(message):
    log_path = os.path.join(BASE_DIR, "alerts.log")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

# Remplacer toaster par notification
def notify(title, message):
    try:
        # Note : Sur Windows, plyer EXIGE un .ico pour l'icône
        app_icon = ICO_ICON_PATH if os.path.exists(ICO_ICON_PATH) else None
        notification.notify(
            title=title,
            message=message,
            app_name=PROJECT_NAME,
            app_icon=app_icon,
            timeout=5
        )
    except Exception as e:
        print(f"Erreur notification : {e}")
        try:
            # Repli sans icône
            notification.notify(
                title=title,
                message=message,
                app_name=PROJECT_NAME,
                timeout=5
            )
        except: pass

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(resource, resource_type="file"):
    """Vérifie un fichier ou une IP sur VirusTotal."""
    if not API_KEY or API_KEY == "votre_cle_api_ici":
        return "NO_API_KEY"

    endpoint = "files" if resource_type == "file" else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{resource}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            return "RATE_LIMITED"
        elif response.status_code == 403:
            return "QUOTA_EXCEEDED"
        return None
    except Exception as e:
        print(f"Erreur connexion API: {e}")
        return None

def scan_file(file_path):
    """Effectue un scan manuel d'un fichier."""
    if not os.path.exists(file_path):
        print(f"Erreur : Le fichier {file_path} n'existe pas.")
        return

    filename = os.path.basename(file_path)
    notify("Analyse en cours", f"{filename}...")
    
    try:
        file_hash = get_file_hash(file_path)
        result = check_virustotal(file_hash, "file")

        if result == "RATE_LIMITED":
            notify("Limite atteinte", "4 scans/min. Réessayez dans un instant.")
        elif result == "NO_API_KEY":
            notify("Erreur Configuration", "Clé API non configurée dans le fichier .env")
        elif result == "QUOTA_EXCEEDED":
            notify("Quota Dépassé", "Limite VirusTotal atteinte.")
        elif result:
            malicious = result['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            if malicious > 0:
                notify("🛡️ Menace Détectée !", f"Attention, {filename} est jugé suspect ({malicious} alertes).")
            else:
                notify("✅ Fichier Sain", f"Le fichier {filename} ne présente aucune menace détectée.")
        else:
            # Cas où le fichier n'est pas encore dans la base VT
            notify("✅ Analyse Terminée", f"Aucune menace signalée sur VirusTotal pour {filename}.")
    except Exception as e:
        print(f"Erreur lors du scan : {e}")

def is_private_ip(ip):
    """Vérifie si une IP est locale (LAN)."""
    try:
        if ip.startswith(("127.", "10.", "192.168.")): return True
        if ip.startswith("172."):
            parts = ip.split('.')
            if 16 <= int(parts[1]) <= 31: return True
        return False
    except:
        return True

def monitor_network():
    """Surveille les connexions réseau actives de manière optimisée."""
    print("Démarrage de la surveillance réseau...")
    while True:
        try:
            # Récupérer toutes les connexions d'un coup
            connections = psutil.net_connections(kind='inet')
            scanned_in_this_pass = 0
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    # Récupérer le nom du processus tôt pour filtrer
                    process_name = "Inconnu"
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except: pass

                    if is_private_ip(remote_ip) or remote_ip in checked_ips:
                        continue
                    
                    if remote_ip in whitelist.get("ips", []) or process_name in whitelist.get("processes", []):
                        continue
                    
                    # Limiter le nombre de scans par minute pour respecter le quota free (4/min)
                    if scanned_in_this_pass >= 4:
                        break 

                    result = check_virustotal(remote_ip, "ip")
                    
                    if result == "RATE_LIMITED":
                        break 
                    
                    scanned_in_this_pass += 1
                    
                    if result and result not in ["QUOTA_EXCEEDED", "NO_API_KEY"]:
                        stats = result['data']['attributes']['last_analysis_stats']
                        malicious = stats.get('malicious', 0)
                        checked_ips[remote_ip] = malicious
                        
                        if malicious > 0:
                            log_alert(f"Détection - IP: {remote_ip}, Processus: {process_name}, Alertes: {malicious}")
                            
                            # On ne notifie que si le seuil est dépassé
                            if malicious >= DETECTION_THRESHOLD:
                                global last_alert_ip, last_alert_proc
                                last_alert_ip = remote_ip
                                last_alert_proc = process_name
                                notify("⚠️ Connexion Suspecte !", f"IP: {remote_ip}\nProcessus: {process_name}\nAlertes: {malicious}")
                    else:
                        checked_ips[remote_ip] = 0 
                        
                time.sleep(0.1) 
        except Exception as e:
            print(f"Erreur monitoring réseau: {e}")
        
        time.sleep(60)

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory: return
        file_path = event.src_path
        filename = os.path.basename(file_path)

        if filename.endswith((".crdownload", ".tmp", ".part")): return

        time.sleep(2)

        try:
            file_hash = get_file_hash(file_path)
            result = check_virustotal(file_hash, "file")

            if result == "RATE_LIMITED":
                return

            if result and result not in ["QUOTA_EXCEEDED", "NO_API_KEY"]:
                malicious = result['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                if malicious > 0:
                    dest_path = os.path.join(QUARANTINE_DIR, filename)
                    try:
                        os.rename(file_path, dest_path)
                        notify("🛡️ Menace Détectée !", f"Fichier dangereux : {filename} a été déplacé en quarantaine ({malicious} alertes).")
                    except:
                        notify("🛡️ Menace Détectée !", f"Attention, le fichier {filename} est jugé suspect ({malicious} alertes).")
                else:
                    notify("✅ Fichier Sain", f"Le fichier {filename} a été vérifié avec succès.")
        except Exception as e:
            print(f"Erreur scan auto : {e}")


# --- SYSTEM TRAY ICON ---
def get_icon_image():
    """Charge le logo personnalisé pour le systray."""
    try:
        if os.path.exists(PNG_ICON_PATH):
            return Image.open(PNG_ICON_PATH)
    except Exception as e:
        print(f"Erreur chargement icone : {e}")
    
    width, height = 64, 64
    image = Image.new('RGB', (width, height), (30, 30, 30))
    dc = ImageDraw.Draw(image)
    dc.rectangle([10, 10, 54, 54], fill=(0, 120, 215))
    return image

def on_exit(icon, item):
    icon.stop()
    os._exit(0)

def open_website(icon, item):
    webbrowser.open(WEBSITE_URL)

def run_tray():
    def get_whitelist_ip_label(item):
        global last_alert_ip
        return f"Ignorer l'IP : {last_alert_ip}" if last_alert_ip else "Aucune alerte IP"

    def get_whitelist_proc_label(item):
        global last_alert_proc
        return f"Ignorer l'appli : {last_alert_proc}" if last_alert_proc else "Aucune alerte App"

    menu = Menu(
        MenuItem(f"{PROJECT_NAME} v{VERSION}", None, enabled=False),
        MenuItem(f"© 2026 {AUTHOR} (Aller sur le site)", open_website),
        MenuItem("---", None, enabled=False),
        MenuItem(get_whitelist_ip_label, add_to_whitelist_ip, enabled=lambda x: last_alert_ip is not None),
        MenuItem(get_whitelist_proc_label, add_to_whitelist_proc, enabled=lambda x: last_alert_proc is not None),
        MenuItem("Voir les alertes", open_logs),
        MenuItem("Editer la Whitelist", open_whitelist_file),
        MenuItem("---", None, enabled=False),
        MenuItem("Quitter", on_exit)
    )
    icon = Icon("VirusTotal-Scanner", get_icon_image(), f"{PROJECT_NAME} v{VERSION} - {AUTHOR}", menu)
    icon.run()

# --- MAIN ---
if __name__ == "__main__":
    try:
        ensure_ico()

        if len(sys.argv) > 1:
            target_path = sys.argv[1]
            if os.path.exists(target_path):
                scan_file(target_path)
                time.sleep(3)
                sys.exit(0)

        print("Vérification de la configuration...")
        if not API_KEY or API_KEY == "votre_cle_api_ici" or not API_KEY:
            print("ERREUR : Clé API manquante dans le .env")
            notify("Erreur Configuration", "Veuillez configurer votre clé API dans le fichier .env")
            sys.exit(1)

        print(f"Initialisation de {PROJECT_NAME} v{VERSION}...")
        
        event_handler = DownloadHandler()
        observer = Observer()
        observer.schedule(event_handler, WATCH_DIR, recursive=False)
        observer.start()

        net_thread = threading.Thread(target=monitor_network, daemon=True)
        net_thread.start()

        print(f"Démarrage de l'icône systray...")
        run_tray()
    except Exception as fatal_error:
        import traceback
        log_alert(f"CRASH FATAL AU DEMARRAGE : {fatal_error}\n{traceback.format_exc()}")
        notify("Erreur Fatale", "L'application a crashé au démarrage. Consultez alerts.log.")
        sys.exit(1)
    finally:
        try:
            observer.stop()
            observer.join()
        except: pass
