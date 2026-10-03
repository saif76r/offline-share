# Builds dist\OfflineShare.exe (single file). Run from the windows\ folder in PowerShell.
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m PyInstaller --onefile --name OfflineShare --paths server `
    --add-data "web;web" --collect-all winsdk --collect-all qrcode server\app.py
Write-Host "Done: dist\OfflineShare.exe  (received\, sent\, logs\ are created next to the .exe)"
