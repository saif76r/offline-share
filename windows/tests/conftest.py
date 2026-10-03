import base64, hashlib, os, shutil, sys, tempfile, time
from pathlib import Path
import pytest

HOME = tempfile.mkdtemp(prefix="osh_")
os.environ["OFFLINESHARE_HOME"] = HOME
os.environ["OFFLINESHARE_DEV"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import app as appmod, crypto, storage
from pairing import PairingManager
from transfer import TransferManager


@pytest.fixture
def srv():
    for d in (storage.RECEIVED, storage.SENT):
        for f in d.iterdir():
            if f.is_file(): f.unlink()
    for f in storage.TMP.glob("*"): f.unlink()
    appmod.pairing, appmod.transfers = PairingManager(), TransferManager()
    appmod._hash_cache.clear()
    appmod.app.config["TESTING"] = True
    return appmod


@pytest.fixture
def http(srv):
    return srv.app.test_client()


@pytest.fixture
def dev(srv, http):
    from devclient import DeviceClient
    return DeviceClient(http, srv.pairing)
