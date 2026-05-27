# VT-SCANNER 🛡️ - Instructions du Projet

Ce fichier contient les directives, l'architecture et les conventions pour le projet VT-SCANNER.

## 📌 Vue d'ensemble
VT-SCANNER est un outil de sécurité local qui surveille les téléchargements, analyse les fichiers via l'API VirusTotal et place les menaces en quarantaine.

## 🏗️ Architecture
- **Surveillance** : Utilisation de `watchdog` pour surveiller les modifications du système de fichiers en temps réel.
- **Analyse** : Hachage SHA-256 local suivi d'une requête API VirusTotal v3.
- **Interface** : 
  - Icône dans la zone de notification (systray) via `pystray`.
  - **Menu Contextuel Windows** : Intégration via le registre pour scanner manuellement via un clic droit.
- **Notifications** : Alertes natives Windows via `win10toast`.
- **Configuration** : Variables d'environnement gérées par `python-dotenv`.

## 📜 Conventions & Style
- **Langue** : Les commentaires dans le code et la documentation sont principalement en **Français**.
- **Style de Code** : Suivre les recommandations PEP 8 pour Python.
- **Nommage** :
  - Fonctions et variables : `snake_case`.
  - Classes : `PascalCase`.
  - Constantes : `UPPER_SNAKE_CASE`.
- **Texte & Typographie** : Pour tout contenu textuel destiné à être affiché ou publié, le texte doit être **justifié** (`text-align: justify`) avec **césure automatique** (`hyphens: auto`) pour garantir un rendu professionnel.

## 🔐 Sécurité
- Le fichier `.env` contenant la clé API VirusTotal ne doit **JAMAIS** être commité sur le dépôt.
- Les fichiers suspects sont déplacés dans un dossier de quarantaine (`QUARANTINE_DIR`) pour éviter toute exécution accidentelle.

## 🛠️ Workflows
- **Ajout de Fonctionnalités** : Modifier `scanner.py`. Le script supporte désormais un argument optionnel (chemin du fichier) pour les scans manuels.
- **Gestion des Dépendances** : Toujours mettre à jour `requirements.txt`.
- **Installation** :
  - `install_startup.ps1` : Lancement automatique au démarrage.
  - `install_context_menu.ps1` : Ajoute l'option "Scanner avec VirusTotal" au clic droit.

## 📝 Historique & Mémoire
*Note : Ce fichier a été initialisé le 27 Mai 2026 d'après l'état actuel du code source.*
