"""Windows Wi-Fi Direct host (WinRT via `winsdk`).

Two modes (never silently falls back to internet/Bluetooth/cable):
  discover (default)  "Like a wireless mouse": this laptop is visible as a Wi-Fi Direct device, it lists nearby
                      phones, and you click Connect (or the phone connects to you). Laptop asks to be group owner.
  legacy              QR mode: autonomous group owner with a known SSID/passphrase (shown in the QR code).

Needs a Wi-Fi adapter/driver with Wi-Fi Direct support (`netsh wlan show drivers`). OFFLINESHARE_DEV=1 = loopback dev only.
"""
import asyncio, os, re, secrets, socket, string, sys, threading

UNAVAILABLE = "Wi-Fi Direct is unavailable on this device.\n\nNo internet or Bluetooth fallback will be used."


class WifiDirectHost:
    def __init__(self, name: str):
        tag = re.sub(r"[^A-Za-z0-9]", "", name)[:10] or "PC"
        self.ssid = f"DIRECT-OS-{tag}"
        self.passphrase = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14))
        self.mode = os.environ.get("OFFLINESHARE_MODE", "discover")
        self.available, self.status, self.message, self.dev = False, "stopped", "", False
        self.last_event = ""
        self._pub = self._watcher = self._listener = self._loop = None
        self._peers, self._connected = {}, []
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- lifecycle
    def start(self, mode=None):
        self.stop()
        self.mode = mode or self.mode
        self.available, self.message, self.status, self.last_event = False, "", "starting", ""
        if os.environ.get("OFFLINESHARE_DEV") == "1":
            self.dev, self.available, self.status = True, True, "dev"
            self.message = "DEV MODE: loopback only - this is NOT Wi-Fi Direct."
            return
        if sys.platform != "win32":
            self.status, self.message = "unavailable", UNAVAILABLE + "\n(Windows required.)"; return
        try:
            from winsdk.windows.devices.wifidirect import (
                WiFiDirectAdvertisementPublisher, WiFiDirectAdvertisementListenStateDiscoverability,
                WiFiDirectConnectionListener)
            from winsdk.windows.security.credentials import PasswordCredential
        except ImportError:
            self.status, self.message = "unavailable", UNAVAILABLE + "\n(Run: pip install winsdk)"; return
        try:
            self._loop = asyncio.new_event_loop()
            threading.Thread(target=self._loop.run_forever, daemon=True).start()
            pub = WiFiDirectAdvertisementPublisher()
            adv = pub.advertisement
            adv.listen_state_discoverability = WiFiDirectAdvertisementListenStateDiscoverability.NORMAL
            if self.mode == "legacy":
                adv.is_autonomous_group_owner_enabled = True
                adv.legacy_settings.is_enabled = True
                adv.legacy_settings.ssid = self.ssid
                cred = PasswordCredential(); cred.password = self.passphrase
                adv.legacy_settings.passphrase = cred
            else:
                self._listener = WiFiDirectConnectionListener()
                self._listener.add_connection_requested(self._on_request)   # phone tapped "Connect" on us
                self._start_watcher()                                       # list nearby phones
            pub.add_status_changed(self._on_status)
            pub.start()
            self._pub = pub
        except Exception as e:      # drivers without Wi-Fi Direct raise here
            self.status, self.message = "unavailable", UNAVAILABLE + f"\n({type(e).__name__}: {e})"

    def stop(self):
        for obj in (self._watcher, self._pub):
            try:
                if obj: obj.stop()
            except Exception: pass
        for d in self._connected:
            try: d.close()
            except Exception: pass
        self._connected, self._peers = [], {}
        self._pub = self._watcher = self._listener = None
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop); self._loop = None

    def _on_status(self, sender, args):
        name = str(args.status).split(".")[-1].lower()       # created / started / stopped / aborted
        self.status = name
        self.available = name == "started"
        if name == "aborted": self.message = UNAVAILABLE
        elif self.available: self.message = ""

    # ---------------------------------------------------------------- discovery ("mouse list")
    def _start_watcher(self):
        from winsdk.windows.devices.wifidirect import WiFiDirectDevice, WiFiDirectDeviceSelectorType
        from winsdk.windows.devices.enumeration import DeviceInformation
        selector = WiFiDirectDevice.get_device_selector(WiFiDirectDeviceSelectorType.ASSOCIATION_ENDPOINT)
        w = DeviceInformation.create_watcher(selector)
        def added(s, info):
            with self._lock: self._peers[info.id] = {"id": info.id, "name": info.name or "Unknown device"}
        def removed(s, upd):
            with self._lock: self._peers.pop(upd.id, None)
        w.add_added(added); w.add_removed(removed)
        w.start(); self._watcher = w

    def peers(self):
        with self._lock: return sorted(self._peers.values(), key=lambda p: p["name"].lower())

    def connect(self, peer_id: str) -> bool:
        if not self._loop or peer_id not in self._peers: return False
        asyncio.run_coroutine_threadsafe(self._connect_to(peer_id), self._loop)
        self.last_event = "Connecting… (accept the invitation on the phone if asked)"
        return True

    def _on_request(self, sender, args):
        try:
            info = args.get_connection_request().device_information
            asyncio.run_coroutine_threadsafe(self._connect_to(info.id), self._loop)
            self.last_event = f"{info.name} is connecting…"
        except Exception as e:
            self.last_event = f"Incoming request failed: {e}"

    async def _connect_to(self, dev_id: str):
        """Link-level connect only. Nothing can be transferred until the phone also pairs with the PIN."""
        from winsdk.windows.devices.wifidirect import WiFiDirectDevice, WiFiDirectConnectionParameters
        from winsdk.windows.devices.enumeration import DeviceInformation, DevicePairingKinds
        try:
            info = await DeviceInformation.create_from_id_async(dev_id)
            if not info.pairing.is_paired:
                custom = info.pairing.custom
                custom.add_pairing_requested(lambda s, a: a.accept())
                await custom.pair_async(DevicePairingKinds.CONFIRM_ONLY)
            params = WiFiDirectConnectionParameters()
            params.group_owner_intent = 15              # we want to be group owner -> phone learns our IP
            dev = await WiFiDirectDevice.from_id_async(dev_id, params)
            self._connected.append(dev)
            self.last_event = "Wi-Fi Direct link up. Enter the PIN on the phone."
        except Exception as e:
            self.last_event = f"Connect failed: {type(e).__name__}: {e}"

    def info(self):
        return {"available": self.available, "dev": self.dev, "status": self.status, "message": self.message,
                "ssid": self.ssid, "mode": self.mode, "event": self.last_event, "peers": self.peers()}


def candidate_ips():
    ips = []
    try:
        ips = [i for i in socket.gethostbyname_ex(socket.gethostname())[2] if not i.startswith(("127.", "169.254."))]
    except OSError:
        pass
    for i in ("192.168.137.1",):
        if i not in ips: ips.append(i)
    return ips
