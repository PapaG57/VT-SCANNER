# ==============================================================================
# SCRIPT : install_context_menu.ps1
# DESCRIPTION : Ajoute une option "Scanner avec VirusTotal" au menu contextuel
#               Windows (clic droit sur un fichier) via HKEY_CURRENT_USER.
# ==============================================================================

$CurrentDir = Get-Location
$PythonW = "$CurrentDir\venv\Scripts\pythonw.exe"
$ScannerScript = "$CurrentDir\scanner.py"
# Utilisation de HKCU pour éviter de demander les droits administrateur
$RegistryPath = "Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\VTScanner"

if (-not (Test-Path $PythonW)) {
    Write-Host "Erreur : Environnement virtuel non trouvé à $PythonW" -ForegroundColor Red
    exit
}

try {
    # 1. Créer la clé principale pour le menu
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RegistryPath -Name "(Default)" -Value "Scanner avec VirusTotal" -ErrorAction Stop
    Set-ItemProperty -Path $RegistryPath -Name "Icon" -Value "$PythonW" -ErrorAction Stop

    # 2. Créer la commande à exécuter
    $CommandPath = "$RegistryPath\command"
    if (-not (Test-Path $CommandPath)) {
        New-Item -Path $CommandPath -Force | Out-Null
    }

    $CommandValue = "`"$PythonW`" `"$ScannerScript`" `"%1`""
    Set-ItemProperty -Path $CommandPath -Name "(Default)" -Value $CommandValue -ErrorAction Stop

    Write-Host "Succès : L'option a été ajoutée au menu contextuel !" -ForegroundColor Green
}
catch {
    Write-Host "Erreur lors de l'écriture dans le registre : $($_.Exception.Message)" -ForegroundColor Red
}
