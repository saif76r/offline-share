@echo off
REM One-time (admin): allow the phone to reach the laptop on any network profile.
REM netsh advfirewall firewall add rule name="OfflineShare" dir=in action=allow protocol=TCP localport=8080 profile=any
cd /d %~dp0
if not exist .venv ( python -m venv .venv && .venv\Scripts\python -m pip install -r requirements.txt )
start "" http://localhost:8080
.venv\Scripts\python server\app.py
