"""OfflineShare Windows server. Run: python server/app.py -> dashboard http://localhost:8080
/api/* and the dashboard are loopback-only. Device endpoints require a signed session (see crypto.py / PROTOCOL.md)."""
import hashlib, io, json, logging, math, os, socket, sys, threading
from functools import wraps
from pathlib import Path
from flask import Flask, Response, jsonify, request, send_file, send_from_directory, abort, g

sys.path.insert(0, str(Path(__file__).parent))
import base64, crypto, storage, security
from pairing import PairingManager
from transfer import TransferManager
from wifidirect import WifiDirectHost, candidate_ips

PORT = 8080
storage.init_dirs()
logging.basicConfig(filename=storage.LOGS / "offlineshare.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("offlineshare")      # never log PINs, keys, passphrases or file contents

app = Flask(__name__, static_folder=None)
pairing, transfers = PairingManager(), TransferManager()
wifi = WifiDirectHost(socket.gethostname())
WEB = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "web"
_hash_cache: dict[str, str] = {}


def local_only(f):
    @wraps(f)
    def w(*a, **k):
        if request.remote_addr not in ("127.0.0.1", "::1"):
            abort(403)
        return f(*a, **k)
    return w


def device_auth(f):
    @wraps(f)
    def w(*a, **k):
        target = request.path + ("?" + request.query_string.decode() if request.query_string else "")
        body_hash = "" if request.method in ("GET", "PATCH") else hashlib.sha256(request.get_data()).hexdigest()
        s = pairing.verify(request.headers.get("X-Session"), request.headers.get("X-Ts"), request.headers.get("X-Nonce"), request.headers.get("X-Sig"),
                           request.method, target, body_hash)
        if not s:
            log.warning("Rejected unauthenticated request %s from %s", request.path, request.remote_addr)
            return jsonify(error="unauthorized"), 401
        g.session = s
        return f(*a, **k)
    return w


# ---------------- dashboard / admin ----------------
@app.get("/")
@local_only
def index(): return send_from_directory(WEB, "index.html")

@app.get("/web/<path:p>")
@local_only
def web(p): return send_from_directory(WEB, p)

@app.get("/api/state")
@local_only
def state():
    return jsonify(
        ips=candidate_ips(), device=socket.gethostname(), pairing=pairing.current(), wifi=wifi.info(),
        sessions=[{"name": s.name, "ip": s.ip, "device_id": s.device_id, "last_seen": s.last_seen} for s in pairing.sessions.values()],
        incoming=transfers.recent(), received=storage.list_dir(storage.RECEIVED),
        outbox=storage.list_dir(storage.SENT), history=storage.history(50))

@app.get("/api/qr.png")
@local_only
def qr_png():
    import qrcode
    payload = {"v": 1, "n": socket.gethostname(), "ip": candidate_ips(), "p": PORT, "s": wifi.ssid,
               "k": wifi.passphrase, "q": pairing.qr_secret_now()}    # temporary: rotates with the PIN
    img = qrcode.make(json.dumps(payload, separators=(",", ":")), box_size=6, border=2)
    buf = io.BytesIO(); img.save(buf, "PNG")
    return Response(buf.getvalue(), mimetype="image/png", headers={"Cache-Control": "no-store"})

@app.post("/api/peers/connect")
@local_only
def peer_connect():
    pid = (request.get_json(silent=True) or {}).get("id", "")
    return jsonify(ok=wifi.connect(pid))

@app.post("/api/wifi/mode")
@local_only
def wifi_mode():
    mode = (request.get_json(silent=True) or {}).get("mode")
    if mode not in ("discover", "legacy"): abort(400)
    wifi.start(mode); log.info("Wi-Fi Direct mode -> %s", mode)
    return jsonify(mode=wifi.mode)

@app.post("/api/transfers/<tid>/<action>")
@local_only
def decide(tid, action):
    if action not in ("accept", "reject"): abort(404)
    try: t = transfers.decide(tid, action == "accept")
    except KeyError: abort(404)
    log.info("Transfer %s %sed", tid[:8], action)
    return jsonify(t.public())

@app.post("/api/outbox")
@local_only
def outbox_add():
    n = 0
    for f in request.files.getlist("files"):
        f.save(security.unique_path(storage.SENT, security.sanitize_filename(f.filename))); n += 1
    return jsonify(added=n)

@app.delete("/api/<area>/<path:name>")
@local_only
def delete(area, name):
    base = {"received": storage.RECEIVED, "outbox": storage.SENT}.get(area) or abort(404)
    try: storage.resolve(base, name).unlink()
    except FileNotFoundError: abort(404)
    return jsonify(ok=True)

@app.get("/api/open/<area>/<path:name>")
@local_only
def open_local(area, name):
    base = {"received": storage.RECEIVED, "outbox": storage.SENT}.get(area) or abort(404)
    try: return send_file(storage.resolve(base, name))
    except FileNotFoundError: abort(404)

@app.post("/api/unpair")
@local_only
def unpair():
    pairing.revoke_all(); log.info("All sessions revoked"); return jsonify(ok=True)


# ---------------- device API ----------------
@app.get("/ping")
def ping(): return jsonify(app="OfflineShare", v=1)

@app.post("/pair")
def pair():
    d = request.get_json(silent=True) or {}
    try:
        s, spub = pairing.pair(d.get("device_id"), d.get("device_name", "Phone"), request.remote_addr,
                               d.get("client_pub", ""), d.get("proof", ""))
    except PermissionError as e:
        log.warning("Pairing failed from %s: %s", request.remote_addr, e)
        return jsonify(error=str(e)), 403
    except ValueError as e:
        return jsonify(error=str(e)), 400
    log.info("Paired device %s (%s)", s.name, s.ip)
    b64 = lambda b: base64.b64encode(b).decode()
    import time
    return jsonify(session_id=s.id, server_pub=b64(spub), server_proof=b64(crypto.server_proof(s.auth_key, s.id)),
                   server_name=socket.gethostname(), server_time=int(time.time()))


def _file_id(p: Path) -> str:
    st = p.stat()
    return hashlib.sha256(f"{p.name}|{st.st_size}|{st.st_mtime_ns}".encode()).hexdigest()[:16]

def _find(fid):
    for f in storage.list_dir(storage.SENT):
        p = storage.SENT / f["name"]
        if _file_id(p) == fid: return p
    return None

@app.get("/files")
@device_auth
def files():
    out = []
    for f in storage.list_dir(storage.SENT):
        p = storage.SENT / f["name"]; fid = _file_id(p)
        if fid not in _hash_cache: _hash_cache[fid] = storage.sha256_file(p)
        out.append({"id": fid, "name": f["name"], "size": f["size"], "sha256": _hash_cache[fid]})
    return jsonify(files=out)

@app.get("/download/<fid>")
@device_auth
def download(fid):
    p = _find(fid) or abort(404)
    try: start = int(request.args.get("chunk", "0"))
    except ValueError: abort(400)
    size = p.stat().st_size
    if start < 0 or start * crypto.CHUNK > size: abort(416)
    remaining = max(0, size - start * crypto.CHUNK)
    key = crypto.file_key(g.session.enc_key, fid)
    device, name = g.session.name, p.name

    def gen():
        for frame in crypto.encrypt_file(p, key, fid, start):
            yield frame
        storage.add_history({"filename": name, "size": size, "direction": "Laptop → Phone", "device": device,
                                 "status": "Sent (awaiting phone verification)", "sha256": _hash_cache.get(fid, ""), "duration": 0})
    return Response(gen(), mimetype="application/octet-stream",
                    headers={"Content-Length": str(crypto.encrypted_length(remaining)), "X-Total-Size": str(size)})

@app.post("/upload/init")
@device_auth
def upload_init():
    d = request.get_json(silent=True) or {}
    try: t = transfers.init(d.get("name"), d.get("size"), d.get("sha256"), g.session.name, g.session.device_id)
    except (ValueError, TypeError) as e: return jsonify(error=str(e)), 400
    log.info("Incoming request %s (%d bytes) from %s", t.name, t.size, t.device)
    return jsonify(id=t.id, state=t.state)

@app.get("/upload/<tid>")
@device_auth
def upload_status(tid):
    try: t = transfers.get(tid, g.session.device_id)
    except KeyError: abort(404)
    return jsonify(state=t.state, offset=transfers.resume_offset(t), error=t.error, final_name=t.final_name)

@app.patch("/upload/<tid>")
@device_auth
def upload_chunk(tid):
    try: off = int(request.headers.get("Upload-Offset", "-1"))
    except ValueError: return jsonify(error="bad offset"), 400
    try:
        t = transfers.get(tid, g.session.device_id)
        t = transfers.receive(t, off, request.stream, g.session.enc_key)
    except KeyError: abort(404)
    except PermissionError as e: return jsonify(error=str(e)), 403
    except ValueError as e: return jsonify(error=str(e)), 409
    return jsonify(state=t.state, offset=t.offset, error=t.error, final_name=t.final_name), (200 if t.state in ("done", "receiving") else 422)


def main():
    wifi.start()
    log.info("Server starting (wifi=%s)", wifi.status)
    print(f"OfflineShare dashboard: http://localhost:{PORT}")
    if not wifi.available: print(wifi.message)
    try: app.run(host="0.0.0.0", port=PORT, threaded=True)
    finally: wifi.stop()

if __name__ == "__main__":
    main()
