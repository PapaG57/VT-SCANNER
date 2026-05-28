$WshShell = New-Object -ComObject WScript.Shell
$ShortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\VT-Scanner.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Chemins absolus basés sur l'emplacement actuel du script
$ProjectRoot = (Get-Location).Path
$ExePath = "$ProjectRoot\dist\VirusTotal Scanner.exe"

$Shortcut.TargetPath = $ExePath
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.Description = "VirusTotal Scanner - Protection VirusTotal"
$Shortcut.IconLocation = $ExePath

$Shortcut.Save()

Write-Host "Raccourci de demarrage mis a jour avec succes !" -ForegroundColor Green
