@echo off
echo Installation du raccourci de demarrage pour VT-SCANNER...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0install_startup.ps1"
if %errorlevel% equ 0 (
    echo.
    echo Succes ! Le raccourci a ete cree dans votre dossier de demarrage.
) else (
    echo.
    echo Une erreur est survenue lors de l'installation.
)
pause
