# 📚 Guide Complet : Exploitation de VT-SCANNER

Ce guide a pour but de vous aider à installer, configurer et utiliser pleinement votre outil **VT-SCANNER**.

---

## 🛠️ 1. Prérequis
Avant de commencer, assurez-vous d'avoir :
- **Python 3.8+** installé sur votre machine.
- Une **Clé API VirusTotal** (Gratuite sur [virustotal.com](https://www.virustotal.com/)).
- Les droits d'administrateur pour l'automatisation au démarrage.

---

## ⚙️ 2. Configuration du fichier `.env`
Le fichier `.env` est le "cerveau" de votre configuration. Ne le partagez jamais !

1. Créez un fichier nommé `.env` à la racine du projet.
2. Copiez et adaptez le contenu suivant :
```env
VT_API_KEY=votre_cle_api_ici
DOWNLOADS_DIR=E:/DOCUMENTS/Téléchargements Web
QUARANTINE_DIR=E:/DOCUMENTS/Scanner/Quarantaine
```
*Note : Utilisez des slashs `/` ou des doubles backslashs `\\` pour les chemins Windows.*

---

## 🚀 3. Installation et Premier Lancement

### Étape 1 : Créer l'environnement virtuel
Ouvrez un terminal (PowerShell) dans le dossier du projet et tapez :
```powershell
python -m venv venv
```

### Étape 2 : Activer l'environnement et installer les dépendances
```powershell
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Étape 3 : Lancer le scanner
```powershell
python scanner.py
```
*Une icône **VT** doit apparaître dans votre barre des tâches.*

---

## 🔄 4. Automatisation (Démarrage Windows)
Pour que le scanner soit toujours actif sans action de votre part :

1. Faites un **clic droit** sur le fichier `install_startup.ps1`.
2. Choisissez **"Exécuter avec PowerShell"**.
3. Le script va créer un raccourci invisible qui lancera le scanner à chaque ouverture de session.

---

## 🖱️ 5. Utilisation au quotidien

### Que se passe-t-il lors d'un téléchargement ?
1. **Détection** : Dès qu'un fichier est fini de télécharger, le scanner le repère.
2. **Analyse** : Il calcule son empreinte numérique unique (SHA-256).
3. **Verdict** :
   - **✅ Sain** : Une notification verte apparaît, vous pouvez ouvrir le fichier.
   - **🛡️ Menace** : Le fichier est **immédiatement déplacé** dans votre dossier Quarantaine. Une notification rouge vous alerte.
   - **❓ Inconnu** : Le fichier n'a jamais été analysé par VirusTotal. Soyez vigilant.

### Le menu Systray (Clic droit sur l'icône VT)
- **VT-SCANNER v1.0.0** : Rappel de la version.
- **Par FG Developpement** : Crédits.
- **Site Web** : Ouvre directement `fgdeveloppement.com`.
- **Quitter** : Arrête la surveillance jusqu'au prochain redémarrage.

---

## 🔍 6. Dépannage (FAQ)

**Q : Je ne vois pas l'icône dans la barre des tâches.**
*R : Vérifiez que vous avez bien activé le `venv` avant de lancer le script. Vérifiez aussi que votre clé API dans le `.env` est correcte.*

**Q : Le scanner ne détecte rien.**
*R : Vérifiez que le chemin `DOWNLOADS_DIR` dans le `.env` correspond exactement à l'endroit où vos fichiers arrivent.*

**Q : Qu'est-ce que je fais d'un fichier en quarantaine ?**
*R : S'il est là, c'est qu'au moins un antivirus l'a jugé suspect. Si vous avez un doute, vous pouvez uploader manuellement le fichier sur le site de VirusTotal pour voir les détails.*

---

## 👨‍💻 7. Maintenance et Évolution
- **Mise à jour des virus** : Automatique via l'API VirusTotal.
- **Mise à jour du code** : Si vous modifiez `scanner.py`, pensez à relancer l'application.
- **Ajout de dossiers** : Vous pouvez modifier le script pour surveiller plusieurs dossiers si nécessaire.

---
*Ce projet est le fruit d'une collaboration entre **FG Developpement** et **Gemini**.*
