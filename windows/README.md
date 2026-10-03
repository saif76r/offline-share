# OfflineShare - Windows app
Python 3.11+, Flask. No Node.js. Needs a Wi-Fi adapter with **Wi-Fi Direct** support.

Check: `netsh wlan show drivers` → look for "Wi-Fi Direct" / "Hosted network supported". Without it the app shows
*"Wi-Fi Direct is unavailable on this device. No internet or Bluetooth fallback will be used."*

## Run
    pip install -r requirements.txt
    python server\app.py            (or double-click run.bat)
Dashboard: http://localhost:8080 — *Nearby devices* lists phones; click **Connect**. `OFFLINESHARE_MODE=legacy` (or the dashboard button) switches to QR mode.
Dashboard: http://localhost:8080 (loopback only - nobody else on the link can open it).
First run, as Administrator (lets the phone reach port 8080 on the Wi-Fi Direct adapter, which Windows treats as a public network):

    netsh advfirewall firewall add rule name="OfflineShare" dir=in action=allow protocol=TCP localport=8080 profile=any

## Package as .exe
    powershell -ExecutionPolicy Bypass -File build_exe.ps1     ->  dist\OfflineShare.exe

## Tests
    pip install -r requirements-dev.txt
    python -m pytest            # 52 tests: pairing, security, files (0 B…100 MB), resume at 10/50/90 %
Set `OFFLINESHARE_DEV=1` to run without Wi-Fi Direct for development (loopback only; the UI says so in red/amber - it is NOT Wi-Fi Direct).

## Folders (next to the app)
`received/` verified files · `sent/` files queued for the phone · `logs/offlineshare.log` (no PINs/keys/passphrases) · `logs/history.json`
