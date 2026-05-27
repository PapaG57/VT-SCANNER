# VT-SCANNER 🛡️

**VT-SCANNER** est un outil d'automatisation de sécurité locale développé par **FG Developpement**. Il surveille en temps réel votre dossier de téléchargements, calcule l'empreinte (hash SHA-256) des nouveaux fichiers et interroge l'API VirusTotal pour détecter d'éventuelles menaces.

## 🚀 Fonctionnalités

- **Surveillance en temps réel** : Détecte instantanément l'ajout de nouveaux fichiers dans le dossier configuré.
- **Analyse VirusTotal** : Utilise l'intelligence de plus de 70 antivirus via l'API VT v3.
- **Quarantaine Automatique** : Déplace immédiatement les fichiers suspects dans un dossier sécurisé.
- **Systray Icon** : Une icône discrète dans la barre des tâches Windows pour gérer l'application.
- **Notifications Natives** : Alertes Windows 10/11 pour chaque résultat d'analyse.
- **Démarrage Automatique** : Script inclus pour lancer l'outil au démarrage de Windows.

## 🛠️ Installation & Configuration

1. **Clé API** : Obtenez une clé API gratuite sur [VirusTotal](https://www.virustotal.com/).
2. **Configuration** : Créez un fichier `.env` à la racine (basé sur `.env.example`) :
   ```env
   VT_API_KEY=votre_cle_ici
   DOWNLOADS_DIR=E:/DOCUMENTS/Téléchargements Web
   QUARANTINE_DIR=E:/DOCUMENTS/Scanner/Quarantaine
   ```
3. **Dépendances** :
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   ```

## 🖥️ Utilisation

### Lancement manuel
```powershell
.\venv\Scripts\activate
python scanner.py
```

### Automatisation Windows
Faites un clic droit sur `install_startup.ps1` et choisissez **Exécuter avec PowerShell**. Cela créera un raccourci dans votre dossier de démarrage Windows.

## 👤 Auteur
- **Développeur** : FG Developpement
- **Version** : 1.0.0
- **Licence** : Propriétaire / FG Developpement
