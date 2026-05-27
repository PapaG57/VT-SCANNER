@echo off
setlocal enabledelayedexpansion

:: ==============================================================================
:: FICHIER : install_context_menu.bat
:: DESCRIPTION : Ajoute l'option "Scanner avec VirusTotal" via REG ADD (CMD).
::               Plus rapide et évite les blocages PowerShell.
:: ==============================================================================

echo [VT-SCANNER] Configuration du menu contextuel...

:: Récupération des chemins absolus
set "BASE_DIR=%~dp0"
set "PYTHONW=%BASE_DIR%venv\Scripts\pythonw.exe"
set "SCANNER_PY=%BASE_DIR%scanner.py"

:: Vérification de l'existence de l'environnement virtuel
if not exist "%PYTHONW%" (
    echo.
    echo ERREUR : L'environnement virtuel est introuvable a :
    echo "%PYTHONW%"
    echo Veuillez d'abord executer l'installation standard.
    pause
    exit /b
)

:: Nettoyage des doubles quotes éventuelles pour les commandes REG
set "REG_PATH=HKCU\Software\Classes\*\shell\VTScanner"

:: 1. Création de la clé principale et du texte du menu
reg add "%REG_PATH%" /ve /t REG_SZ /d "Scanner avec VirusTotal" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERREUR : Impossible d'ecrire dans le registre. 
    echo Verifiez vos droits d'acces.
    pause
    exit /b
)

:: 2. Ajout de l'icône (utilise l'icône de pythonw.exe)
reg add "%REG_PATH%" /v "Icon" /t REG_SZ /d "\"%PYTHONW%\"" /f >nul 2>&1

:: 3. Configuration de la commande
:: Note : on utilise double %%1 pour échapper le %1 dans le fichier .bat
reg add "%REG_PATH%\command" /ve /t REG_SZ /d "\"%PYTHONW%\" \"%SCANNER_PY%\" \"%%1\"" /f >nul 2>&1

echo.
echo SUCCES : L'option a ete ajoutee au menu contextuel !
echo Vous pouvez maintenant faire un clic droit sur un fichier.
echo.
pause
