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
set "EXE_PATH=%BASE_DIR%dist\VirusTotal Scanner.exe"

:: Vérification de l'existence de l'exécutable
if not exist "%EXE_PATH%" (
    echo.
    echo ERREUR : L'executable est introuvable a :
    echo "%EXE_PATH%"
    echo Veuillez d'abord compiler le projet.
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

:: 2. Ajout de l'icône (utilise l'icône de l'exécutable)
reg add "%REG_PATH%" /v "Icon" /t REG_SZ /d "\"%EXE_PATH%\"" /f >nul 2>&1

:: 3. Configuration de la commande
reg add "%REG_PATH%\command" /ve /t REG_SZ /d "\"%EXE_PATH%\" \"%%1\"" /f >nul 2>&1

echo.
echo SUCCES : L'option a ete ajoutee au menu contextuel !
echo Vous pouvez maintenant faire un clic droit sur un fichier.
echo.
pause
