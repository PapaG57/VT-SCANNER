# VT-SCANNER 🛡️ - Instructions du Projet

Ce fichier contient les directives, l'architecture et les conventions pour le projet VT-SCANNER.

## 📌 Vue d'ensemble
VT-SCANNER est une suite de sécurité artisanale "Maison" complète qui utilise l'API VirusTotal pour protéger la machine contre les fichiers, liens et connexions malveillants.

## 🏗️ Architecture
Le projet repose sur quatre piliers de protection :

1.  **Surveillance Fichiers (Temps Réel)** : Utilisation de `watchdog` pour surveiller le dossier de téléchargements. Tout nouveau fichier est haché (SHA-256) et vérifié.
2.  **Scan Manuel (Menu Contextuel)** : Intégration Windows via le registre pour scanner n'importe quel fichier via un clic droit (script `.bat` optimisé).
3.  **Extension Navigateur (Lien)** : Extension Chrome/Edge permettant d'analyser un lien avant de cliquer via le menu contextuel du navigateur.
4.  **Surveillance Réseau (EDR)** : Analyse en tâche de fond des connexions IP établies via `psutil` avec identification des processus.

## 🛠️ Composants & Dépendances
- **`scanner.py`** : Cœur du système.
- **`extension/`** : Code source de l'extension de navigateur.
- **`install_context_menu.bat`** : Installation du menu contextuel Windows (méthode native `reg add`).
- **Bibliothèques clés** : `plyer` (notifications stables), `pystray` (icône systray), `psutil` (réseau), `watchdog` (fichiers).

## 📜 Conventions & Style
- **Langue** : Commentaires et documentation en **Français**.
- **Interface** : Utilisation du logo personnalisé (`tray_icon.png`) pour le systray et les notifications.
- **Typographie** : Tout texte affiché doit être **justifié** (`text-align: justify`) avec **césure automatique** (`hyphens: auto`).

## 🔐 Sécurité & Performance
- **Gestion des Quotas** : Cache local (`checked_ips`) pour respecter la limite de 4 requêtes/minute de l'API gratuite.
- **Robustesse** : Remplacement de `win10toast` par `plyer` pour éviter les erreurs de dépendances (`pkg_resources`).
- **Isolation** : Fonctionne en complément des antivirus classiques sans conflit.

## 📝 Historique des Versions
- **v1.0.0** : Surveillance de base des téléchargements.
- **v1.1.0** : Ajout du menu contextuel Windows.
- **v1.2.0** : Ajout du monitoring réseau, de l'extension de navigateur et passage à `plyer`.

*Dernière mise à jour : 27 Mai 2026 par Gemini CLI & FG Developpement.*
