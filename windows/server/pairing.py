"""Pairing + authenticated sessions.
The PIN/QR secret is never sent: the phone proves knowledge with an HMAC and both sides mix it into the key derivation."""
import secrets, threading, time
from dataclasses import dataclass, field
import crypto, security

PIN_TTL = 120
MAX_ATTEMPTS = 5
SESSION_TTL = 12 * 3600
CLOCK_SKEW = 60


@dataclass
class Session:
    id: str
    device_id: str
    name: str
    ip: str
    enc_key: bytes
    auth_key: bytes
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class PairingManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.sessions: dict[str, Session] = {}
        self._seen: dict[str, float] = {}
        self._rotate()

    def _rotate(self):
        self.pin = security.new_pin()
        self.qr_secret = secrets.token_urlsafe(16)
        self.expires = time.time() + PIN_TTL
        self.attempts = 0

    def current(self):
        with self._lock:
            if time.time() > self.expires:
                self._rotate()
            return {"pin": self.pin, "expires_in": int(self.expires - time.time())}

    def qr_secret_now(self):
        self.current()
        return self.qr_secret

    def pair(self, device_id, name, ip, client_pub_b64, proof_b64):
        import base64
        try:
            client_pub = base64.b64decode(client_pub_b64, validate=True)
            proof = base64.b64decode(proof_b64, validate=True)
            device_id = str(device_id)[:64]
            if not device_id or len(client_pub) != 65:
                raise ValueError
        except Exception:
            raise ValueError("malformed pairing request")
        with self._lock:
            if time.time() > self.expires:
                self._rotate()
                raise PermissionError("PIN expired")
            self.attempts += 1
            if self.attempts > MAX_ATTEMPTS:
                self._rotate()
                raise PermissionError("Too many attempts; new PIN generated")
            secret = next((s for s in (self.pin, self.qr_secret)
                           if security.safe_equal_bytes(crypto.client_proof(s, device_id, client_pub), proof)), None)
            if secret is None:
                raise PermissionError("Invalid PIN")
            priv = crypto.new_keypair()
            spub = crypto.pub_bytes(priv)
            enc, auth = crypto.derive_session_keys(crypto.ecdh(priv, client_pub), secret, client_pub, spub)
            s = Session(secrets.token_hex(16), device_id, (str(name)[:64] or "Phone"), ip, enc, auth)
            self.sessions = {k: v for k, v in self.sessions.items() if v.device_id != device_id}
            self.sessions[s.id] = s
            self._rotate()                      # secrets are single use
            return s, spub

    def verify(self, sid, ts, nonce, sig, method, target, body_hash):
        """Return Session if the signed request is valid, fresh and not replayed; else None."""
        with self._lock:
            now = time.time()
            s = self.sessions.get(sid or "")
            if not s or now - s.created > SESSION_TTL:
                return None
            try:
                ts = int(ts)
            except (TypeError, ValueError):
                return None
            if abs(now - ts) > CLOCK_SKEW:
                return None
            if not security.safe_equal(crypto.sign_request(s.auth_key, sid, ts, nonce or "", method, target, body_hash), sig or ""):
                return None
            self._seen = {k: v for k, v in self._seen.items() if now - v < 2 * CLOCK_SKEW}
            if not nonce or len(nonce) > 64 or (sid + nonce) in self._seen:
                return None
            self._seen[sid + nonce] = now
            s.last_seen = now
            return s

    def revoke_all(self):
        with self._lock:
            self.sessions.clear()
            self._rotate()
