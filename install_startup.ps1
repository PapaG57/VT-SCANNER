$s = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\VT-Scanner.lnk")
$s.TargetPath = "powershell.exe"
$s.Arguments = "-WindowStyle Hidden -Command ""cd '$PWD'; .\venv\Scripts\python.exe scanner.py"""
$s.IconLocation = "powershell.exe"
$s.Save()
