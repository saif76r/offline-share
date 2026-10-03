"""Storage: directories, transfer history, hashing, file listings."""
import hashlib, json, os, sys, threading, time, uuid
from pathlib import Path
from security import ensure_inside, sanitize_filename

def _root():
    if os.environ.get("OFFLINESHARE_HOME"):
        return Path(os.environ["OFFLINESHARE_HOME"])
    if getattr(sys, "frozen", False):          # PyInstaller exe: keep data next to the .exe
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


ROOT = _root()
RECEIVED, SENT, LOGS = ROOT / "received", ROOT / "sent", ROOT / "logs"
TMP = ROOT / "received" / ".partial"
HISTORY = LOGS / "history.json"
_lock = threading.Lock()
CHUNK = 1024 * 1024  # 1 MB


def init_dirs():
    for d in (RECEIVED, SENT, LOGS, TMP):
        d.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def add_history(entry: dict):
    entry = {"ts": time.time(), **entry}
    with _lock:
        items = _load()
        items.append(entry)
        HISTORY.write_text(json.dumps(items[-1000:], indent=1), encoding="utf-8")


def _load():
    try:
        return json.loads(HISTORY.read_text(encoding="utf-8"))
    except Exception:
        return []


def history(limit=100):
    with _lock:
        return list(reversed(_load()[-limit:]))


def list_dir(directory: Path):
    out = []
    for p in sorted(directory.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if p.is_file():
            st = p.stat()
            out.append({"id": p.name, "name": p.name, "size": st.st_size, "mtime": st.st_mtime})
    return out


def resolve(directory: Path, name: str) -> Path:
    p = ensure_inside(directory, directory / sanitize_filename(name))
    if not p.is_file():
        raise FileNotFoundError(name)
    return p


def new_id() -> str:
    return uuid.uuid4().hex
