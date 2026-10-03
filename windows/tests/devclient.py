"""Reference phone client in Python - the executable spec the Kotlin client mirrors."""
import base64, hashlib, json, secrets, time
import crypto

b64 = lambda b: base64.b64encode(b).decode()


class DeviceClient:
    def __init__(self, http, pairing, name="Test Phone", device_id="dev-1"):
        self.http, self.pairing, self.name, self.device_id = http, pairing, name, device_id
        self.sid = None

    def pair(self, secret=None):
        secret = secret or self.pairing.pin
        priv = crypto.new_keypair(); cpub = crypto.pub_bytes(priv)
        r = self.http.post("/pair", json={"device_id": self.device_id, "device_name": self.name, "client_pub": b64(cpub),
                                          "proof": b64(crypto.client_proof(secret, self.device_id, cpub))})
        if r.status_code != 200: return r
        d = r.get_json(); spub = base64.b64decode(d["server_pub"])
        self.enc, self.auth = crypto.derive_session_keys(crypto.ecdh(priv, spub), secret, cpub, spub)
        assert base64.b64decode(d["server_proof"]) == crypto.server_proof(self.auth, d["session_id"])
        self.sid, self.skew = d["session_id"], d["server_time"] - int(time.time())
        return r

    def headers(self, method, target, body=b"", ts=None):
        ts = ts if ts is not None else int(time.time()) + self.skew
        bh = "" if method in ("GET", "PATCH") else hashlib.sha256(body).hexdigest()
        nonce = secrets.token_hex(8)
        return {"X-Session": self.sid, "X-Ts": str(ts), "X-Nonce": nonce,
                "X-Sig": crypto.sign_request(self.auth, self.sid, ts, nonce, method, target, bh)}

    def call(self, method, target, body=None, extra=None, ts=None):
        raw = json.dumps(body).encode() if isinstance(body, dict) else (body or b"")
        h = self.headers(method, target, raw if isinstance(body, dict) else b"", ts)
        h.update(extra or {})
        if isinstance(body, dict): h["Content-Type"] = "application/json"
        return self.http.open(target, method=method, data=raw, headers=h)

    # ---- phone -> laptop
    def init_upload(self, name, data):
        return self.call("POST", "/upload/init", {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}).get_json()["id"]

    def patch(self, tid, data, offset=0, max_chunks=None, tamper=False):
        key, frames, i = crypto.file_key(self.enc, tid), [], offset // crypto.CHUNK
        for pos in range(offset, len(data), crypto.CHUNK):
            if max_chunks is not None and len(frames) >= max_chunks: break
            frames.append(crypto.seal(key, tid, i, data[pos:pos + crypto.CHUNK])); i += 1
        body = b"".join(frames)
        if tamper and body: body = body[:30] + bytes([body[30] ^ 1]) + body[31:]
        return self.call("PATCH", f"/upload/{tid}", body, {"Upload-Offset": str(offset)})

    # ---- laptop -> phone
    def download(self, f, start_chunk=0, limit=None):
        r = self.call("GET", f"/download/{f['id']}?chunk={start_chunk}")
        stream, key, i, out = __import__("io").BytesIO(r.data), crypto.file_key(self.enc, f["id"]), start_chunk, b""
        while (ct := crypto.read_frame(stream)) is not None:
            out += crypto.open_frame(key, f["id"], i, ct); i += 1
        return out
