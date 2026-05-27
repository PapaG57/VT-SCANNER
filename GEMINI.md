# VT-SCANNER 🛡️ - Instructions du Projet

Ce fichier contient les directives, l'architecture et les conventions pour le projet VT-SCANNER.

## 📌 Vue d'ensemble
VT-SCANNER est une suite de sécurité artisanale "Maison" qui utilise l'API VirusTotal pour protéger la machine contre les fichiers, liens et connexions malveillants.

## 🏗️ Architecture
Le projet repose sur quatre piliers de protection :

1.  **Surveillance Fichiers (Temps Réel)** : Utilisation de `watchdog` pour surveiller le dossier de téléchargements. Tout nouveau fichier est haché (SHA-256) et vérifié.
2.  **Scan Manuel (Menu Contextuel)** : Intégration Windows via le registre pour scanner n'importe quel fichier via un clic droit.
3.  **Extension Navigateur (Lien)** : Extension Chrome/Edge permettant d'analyser un lien avant de cliquer (clic droit sur un lien).
4.  **Surveillance Réseau (EDR)** : Analyse en tâche de fond des connexions IP établies via `psutil`.

## 🛠️ Composants du Projet
- **`scanner.py`** : Cœur du système (Fichiers + Réseau + Systray).
- **`extension/`** : Code source de l'extension de navigateur.
- **`install_startup.ps1`** : Configuration du lancement automatique.
- **`install_context_menu.bat`** : Installation ultra-rapide du menu contextuel Windows.

## 📜 Conventions & Style
- **Langue** : Commentaires et documentation en **Français**.
- **Typographie** : Tout texte affiché doit être **justifié** (`text-align: justify`) avec **césure automatique** (`hyphens: auto`) pour un rendu professionnel.
- **Code** : Respect strict de PEP 8, utilisation de threads pour ne pas bloquer l'interface (systray).

## 🔐 Sécurité & Performance
- **Gestion des Quotas** : Utilisation d'un cache local (`checked_ips`) pour respecter la limite de 4 requêtes/minute de l'API gratuite VT.
- **Confidentialité** : La clé API est stockée dans `.env` (local) ou `chrome.storage.local` (extension) et ne quitte jamais la machine.
- **Interactions** : Conçu pour fonctionner en complément de Windows Defender et MalwareBytes sans conflit.

## 📝 Historique
- **v1.0.0** : Surveillance de base des téléchargements.
- **v1.1.0** : Ajout du menu contextuel Windows (.bat).
- **v1.2.0** : Ajout de la surveillance réseau (IP) et de l'extension de navigateur.

*Dernière mise à jour : 27 Mai 2026 par Gemini CLI & FG Developpement.*
