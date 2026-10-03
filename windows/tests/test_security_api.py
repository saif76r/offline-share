import hashlib, os, time
import storage

def test_unauthenticated_blocked(http):
    assert http.get("/files").status_code == 401
    assert http.post("/upload/init", json={}).status_code == 401

def test_bad_signature(dev):
    dev.pair(); h = dev.headers("GET", "/files"); h["X-Sig"] = "0" * 64
    assert dev.http.get("/files", headers=h).status_code == 401

def test_unknown_session(dev):
    dev.pair(); h = dev.headers("GET", "/files"); h["X-Session"] = "deadbeef"
    assert dev.http.get("/files", headers=h).status_code == 401

def test_expired_timestamp(dev):
    dev.pair(); assert dev.call("GET", "/files", ts=int(time.time()) - 3600).status_code == 401

def test_replay_rejected(dev):
    dev.pair(); h = dev.headers("GET", "/files")
    assert dev.http.get("/files", headers=h).status_code == 200
    assert dev.http.get("/files", headers=h).status_code == 401

def test_tampered_target_rejected(dev):
    dev.pair(); h = dev.headers("GET", "/files")
    assert dev.http.get("/files?x=1", headers=h).status_code == 401

def test_path_traversal_name_stays_inside(dev, srv):
    dev.pair(); tid = dev.init_upload("../../../evil.txt", b"x"); srv.transfers.decide(tid, True); dev.patch(tid, b"x")
    assert (storage.RECEIVED / "evil.txt").exists()
    assert not (storage.RECEIVED.parent.parent / "evil.txt").exists()

def test_wrong_sha256_rejected_and_discarded(dev, srv):
    dev.pair()
    r = dev.call("POST", "/upload/init", {"name": "a.bin", "size": 4, "sha256": "0" * 64}); tid = r.get_json()["id"]
    srv.transfers.decide(tid, True); r = dev.patch(tid, b"abcd")
    assert r.get_json()["state"] == "failed" and "SHA-256" in r.get_json()["error"]
    assert not list(storage.RECEIVED.glob("a.bin"))

def test_tampered_ciphertext_rejected(dev, srv):
    dev.pair(); data = os.urandom(5000); tid = dev.init_upload("t.bin", data); srv.transfers.decide(tid, True)
    assert dev.patch(tid, data, tamper=True).status_code == 409
    assert not (storage.RECEIVED / "t.bin").exists()

def test_oversized_declaration_rejected(dev):
    dev.pair(); r = dev.call("POST", "/upload/init", {"name": "a", "size": 10**15, "sha256": "0" * 64}); assert r.status_code == 400

def test_malformed_requests(dev):
    dev.pair()
    assert dev.call("POST", "/upload/init", {"name": "a", "size": "x", "sha256": "z"}).status_code == 400
    assert dev.http.post("/pair", data="not json").status_code in (400, 403)

def test_other_device_cannot_touch_transfer(dev, srv, http):
    from devclient import DeviceClient
    dev.pair(); tid = dev.init_upload("a", b"1"); srv.transfers.decide(tid, True)
    other = DeviceClient(http, srv.pairing, device_id="other"); other.pair()
    assert other.patch(tid, b"1").status_code == 404

def test_oversized_chunk_frame_rejected(dev, srv):
    dev.pair(); tid = dev.init_upload("a", b"1"); srv.transfers.decide(tid, True)
    r = dev.call("PATCH", f"/upload/{tid}", (2**31).to_bytes(4, "big") + b"x", {"Upload-Offset": "0"}); assert r.status_code == 409
