@echo off
:: ==============================================================================
:: FICHIER : install_context_menu.bat
:: DESCRIPTION : Lance le script PowerShell pour ajouter l'option "Scanner avec
::               VirusTotal" au menu contextuel.
:: ==============================================================================

echo [VT-SCANNER] Configuration du menu contextuel...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_context_menu.ps1"

echo.
pause
