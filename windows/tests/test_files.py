import hashlib, os
import pytest, storage

def send(dev, srv, name, data, accept=True):
    dev.pair(); tid = dev.init_upload(name, data)
    if accept: srv.transfers.decide(tid, True)
    return tid, dev.patch(tid, data)

@pytest.mark.parametrize("size", [0, 1024, 1 << 20, (1 << 20) + 1, 10 * (1 << 20)])
def test_sizes(dev, srv, size):
    data = os.urandom(size); tid, r = send(dev, srv, "f.bin", data)
    assert r.get_json()["state"] == "done"
    assert (storage.RECEIVED / "f.bin").read_bytes() == data

@pytest.mark.slow
def test_100mb(dev, srv):
    data = os.urandom(100 * (1 << 20)); tid, r = send(dev, srv, "big.bin", data)
    assert r.get_json()["state"] == "done"
    assert storage.sha256_file(storage.RECEIVED / "big.bin") == hashlib.sha256(data).hexdigest()

def test_unicode_name(dev, srv):
    tid, r = send(dev, srv, "résumé 文件 🙂.txt", b"hi"); assert (storage.RECEIVED / "résumé 文件 🙂.txt").exists()

def test_duplicate_names_never_overwrite(dev, srv):
    send(dev, srv, "d.pdf", b"one"); dev.pair(); 
    t = dev.init_upload("d.pdf", b"two"); srv.transfers.decide(t, True); dev.patch(t, b"two")
    assert (storage.RECEIVED / "d.pdf").read_bytes() == b"one" and (storage.RECEIVED / "d (1).pdf").read_bytes() == b"two"

def test_must_be_accepted_first(dev, srv):
    tid, r = send(dev, srv, "x.txt", b"data", accept=False); assert r.status_code == 403
    assert not (storage.RECEIVED / "x.txt").exists()

def test_rejected(dev, srv):
    dev.pair(); tid = dev.init_upload("x.txt", b"d"); srv.transfers.decide(tid, False)
    assert dev.patch(tid, b"d").status_code == 403

def test_laptop_to_phone_roundtrip(dev, srv):
    data = os.urandom(3 * (1 << 20) + 17); (storage.SENT / "doc.bin").write_bytes(data); dev.pair()
    f = dev.call("GET", "/files").get_json()["files"][0]
    assert f["sha256"] == hashlib.sha256(data).hexdigest()
    assert dev.download(f) == data

def test_download_resume(dev, srv):
    data = os.urandom(3 * (1 << 20) + 5); (storage.SENT / "doc.bin").write_bytes(data); dev.pair()
    f = dev.call("GET", "/files").get_json()["files"][0]
    assert dev.download(f, start_chunk=2) == data[2 * (1 << 20):]
