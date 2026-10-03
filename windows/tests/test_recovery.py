import hashlib, os
import pytest, storage

CH = 1 << 20

@pytest.mark.parametrize("pct", [10, 50, 90])
def test_disconnect_and_resume(dev, srv, pct):
    data = os.urandom(10 * CH + 123); dev.pair()
    tid = dev.init_upload("big.bin", data); srv.transfers.decide(tid, True)
    n = max(1, int(11 * pct / 100))
    r = dev.patch(tid, data, 0, max_chunks=n)                      # connection "drops" after n chunks
    assert r.get_json()["state"] == "failed" and "resume" in r.get_json()["error"]
    st = dev.call("GET", f"/upload/{tid}").get_json()
    assert st["offset"] == n * CH                                   # server tells us where to resume
    r = dev.patch(tid, data, st["offset"])
    assert r.get_json()["state"] == "done"
    assert storage.sha256_file(storage.RECEIVED / "big.bin") == hashlib.sha256(data).hexdigest()

def test_resume_wrong_offset_rejected(dev, srv):
    data = os.urandom(3 * CH); dev.pair(); tid = dev.init_upload("a", data); srv.transfers.decide(tid, True)
    dev.patch(tid, data, 0, max_chunks=1)
    assert dev.patch(tid, data, 2 * CH).status_code == 409

def test_mid_frame_cut_discards_partial_chunk(dev, srv):
    data = os.urandom(3 * CH); dev.pair(); tid = dev.init_upload("a", data); srv.transfers.decide(tid, True)
    import crypto
    frames = [crypto.seal(crypto.file_key(dev.enc, tid), tid, i, data[i*CH:(i+1)*CH]) for i in range(3)]
    dev.call("PATCH", f"/upload/{tid}", frames[0] + frames[1][: CH // 2], {"Upload-Offset": "0"})
    assert dev.call("GET", f"/upload/{tid}").get_json()["offset"] == CH
