# OfflineShare
Offline file sharing over **Wi-Fi Direct only** — no internet, router, Bluetooth, cable or cloud, and no silent fallback to any of them.
Works **Android ↔ Windows** and **Android ↔ Android** (install the same app on both phones).

```
android/    Kotlin + Jetpack Compose (Material 3) app        protocol/   PROTOCOL.md, test_vectors.json
windows/    Python/Flask server + dashboard + tests          
```

## Using it (like pairing a wireless mouse)
**Phone ↔ Laptop**
1. Laptop: run OfflineShare (`windows/run.bat`). Dashboard → *Nearby devices* lists phones that have the app open. Phone: *Home → Nearby devices* lists the laptop 💻.
2. Click **Connect** on either side (accept the Wi-Fi Direct invitation if Android asks). The laptop shows a 6-digit **PIN**; the phone asks for it → **Pair Device**.
3. Phone → laptop: *Send → Select Files → Send*, press **Accept** on the laptop. Laptop → phone: pick files in the dashboard, then on the phone *Receive → Refresh → Accept All*.
(If the device list doesn't work on your hardware: dashboard **Switch to QR mode**, then phone **Scan laptop QR code**.)

**Phone ↔ Phone**
1. Receiving phone: *Home → Receive from another phone* → ON (shows a PIN).
2. Sending phone: *Home → Nearby devices* → tap the receiving phone → enter the PIN → *Send → Select Files → Send*.
3. Receiving phone taps **Accept**. Files land in `Downloads/OfflineShare/Received`.

## Build
**Windows:** `windows/README.md` (run, tests, `.exe` via PyInstaller).
**Android APK:** open `android/` in Android Studio (JDK 17), let Gradle sync, then *Build ▸ Build APK(s)* or in `android/`:

    gradlew assembleDebug           -> app/build/outputs/apk/debug/app-debug.apk
    gradlew testDebugUnitTest       # Kotlin crypto == Python crypto, plus a Kotlin phone-to-phone server test
Install on both phones: `adb install app-debug.apk`. Android 10+ with Wi-Fi Direct. Allow Camera, Nearby devices (Location on ≤ Android 12), Notifications.

## Security (summary — details in protocol/PROTOCOL.md)
PIN/QR pairing (single-use, 120 s, 5 tries) → ECDH + HKDF session keys with mutual proof · every request HMAC-signed with nonce/timestamp (replay-proof) ·
AES-256-GCM per 1 MiB chunk · SHA-256 verified on disk before "success" · filenames sanitised, no overwrite (`name (1).ext`) · dashboard loopback-only.

## Honest status — read this
* **Tested (automated):** the Windows server — 52 tests passing (pairing, signing/replay, encryption, 0 B…100 MB files, resume at 10/50/90 %, path traversal, wrong hash, tampering, QR image).
* **Written but NOT compiled or run by me:** the entire Android app (incl. the phone-to-phone `ReceiveServer`) and the Windows Wi-Fi Direct code (`wifidirect.py`). Kotlin tests exist (`CryptoTest` vs Python vectors, `ReceiveServerTest` end-to-end) — run `gradlew testDebugUnitTest` first. Expect a few compile errors on the first build; send me the output and I'll fix them.
* **Wi-Fi Direct is driver/phone dependent.** Windows↔Android discovery is the most fragile part (Windows adapter must support Wi-Fi Direct: `netsh wlan show drivers`). If it fails you'll see "Wi-Fi Direct is unavailable on this device. No internet or Bluetooth fallback will be used." QR mode is the backup; the phone also has an explicit, user-tapped *Join via Wi-Fi (direct)* button — never automatic.
* If the link IP changes (Wi-Fi toggled), the phone's **Reconnect** re-finds the laptop and keeps the session keys; the dashboard/QR update by themselves.
* Android needs the `INTERNET` permission for any socket, even local; the app never contacts the internet.
* Filenames are authenticated but not encrypted (file contents are). Transfers run while the app is open (wake + Wi-Fi locks); no background service yet. Windows dev server is used so uploads stream/resume.
