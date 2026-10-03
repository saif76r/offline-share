import time

def test_pairing_succeeds(dev): assert dev.pair().status_code == 200 and dev.sid

def test_invalid_pin_rejected(dev):
    assert dev.pair("000000" if dev.pairing.pin != "000000" else "111111").status_code == 403

def test_pin_single_use_and_rotates(dev):
    old = dev.pairing.pin; dev.pair()
    assert dev.pairing.pin != old

def test_expired_pin(dev):
    dev.pairing.expires = time.time() - 1
    assert dev.pair().status_code == 403

def test_bruteforce_locked_out(dev):
    pin = dev.pairing.pin
    for _ in range(5): dev.pair("999999" if pin != "999999" else "888888")
    assert dev.pair(pin).status_code == 403            # PIN rotated after too many tries

def test_qr_secret_pairs(dev): assert dev.pair(dev.pairing.qr_secret).status_code == 200

def test_ping(http): assert http.get("/ping").get_json()["app"] == "OfflineShare"

def test_admin_api_is_loopback_only(srv):
    c = srv.app.test_client()
    assert c.get("/api/state", environ_overrides={"REMOTE_ADDR": "192.168.137.5"}).status_code == 403
    assert c.get("/api/state").status_code == 200

def test_wifi_mode_switch_and_peers_api(srv):
    c = srv.app.test_client()
    assert c.post("/api/wifi/mode", json={"mode": "legacy"}).get_json()["mode"] == "legacy"
    assert c.post("/api/wifi/mode", json={"mode": "bogus"}).status_code == 400
    assert c.post("/api/wifi/mode", json={"mode": "discover"}).get_json()["mode"] == "discover"
    assert c.post("/api/peers/connect", json={"id": "nope"}).get_json()["ok"] is False
    st = c.get("/api/state").get_json()["wifi"]; assert st["mode"] == "discover" and st["peers"] == []

def test_qr_png(srv):
    r = srv.app.test_client().get("/api/qr.png"); assert r.status_code == 200 and r.data[:4] == b"\x89PNG"
