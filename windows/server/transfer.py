"""Incoming (phone -> laptop) transfers: init -> user accepts -> resumable encrypted upload -> SHA-256 verify."""
import threading, time
from dataclasses import dataclass, field
from pathlib import Path
import crypto, storage, security

MAX_FILE_SIZE = 20 * 1024**3


@dataclass
class Incoming:
    id: str
    name: str
    size: int
    sha256: str
    device: str
    device_id: str
    state: str = "pending"     # pending|accepted|rejected|receiving|done|failed
    offset: int = 0
    started: float = field(default_factory=time.time)
    error: str = ""
    final_name: str = ""
    tmp: Path = None

    def public(self):
        return {k: getattr(self, k) for k in ("id", "name", "size", "sha256", "device", "state", "offset", "error", "final_name")}


class TransferManager:
    def __init__(self):
        self.items: dict[str, Incoming] = {}
        self.lock = threading.Lock()

    def init(self, name, size, sha256, device, device_id) -> Incoming:
        size = int(size)
        if size < 0 or size > MAX_FILE_SIZE:
            raise ValueError("invalid or oversized file")
        sha256 = str(sha256).lower()
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("invalid sha256")
        t = Incoming(storage.new_id(), security.sanitize_filename(name), size, sha256, device, device_id)
        t.tmp = storage.TMP / f"{t.id}.part"
        with self.lock:
            self.items[t.id] = t
        return t

    def get(self, tid, device_id=None) -> Incoming:
        t = self.items.get(tid)
        if not t or (device_id and t.device_id != device_id):
            raise KeyError(tid)
        return t

    def decide(self, tid, accept: bool):
        t = self.get(tid)
        if t.state == "pending":
            t.state = "accepted" if accept else "rejected"
        return t

    def resume_offset(self, t: Incoming) -> int:
        """Bytes safely stored. Always a whole number of chunks (partial chunks are discarded)."""
        if t.state == "done":
            return t.size
        have = t.tmp.stat().st_size if t.tmp.exists() else 0
        safe = (have // crypto.CHUNK) * crypto.CHUNK
        if safe != have:
            with open(t.tmp, "r+b") as f:
                f.truncate(safe)
        return safe

    def receive(self, t: Incoming, offset: int, stream, enc_key: bytes) -> Incoming:
        if t.state not in ("accepted", "receiving", "failed"):
            raise PermissionError(f"transfer is {t.state}")
        have = self.resume_offset(t)
        if offset != have:
            raise ValueError(f"offset mismatch; server has {have}")
        t.state, t.offset, t.error = "receiving", have, ""
        key, idx = crypto.file_key(enc_key, t.id), have // crypto.CHUNK
        try:
            with open(t.tmp, "ab") as f:
                while t.offset < t.size:
                    ct = crypto.read_frame(stream)
                    if ct is None:
                        break
                    if len(ct) != min(crypto.CHUNK, t.size - t.offset) + crypto.TAG:
                        raise ValueError("unexpected chunk size")
                    plain = crypto.open_frame(key, t.id, idx, ct)
                    f.write(plain)
                    t.offset += len(plain)
                    idx += 1
        except EOFError:
            t.state, t.error = "failed", "interrupted - resume available"
            return t
        except Exception as e:
            t.state, t.error = "failed", str(e)
            raise
        if t.offset < t.size:
            t.state, t.error = "failed", "interrupted - resume available"
            return t
        return self._finalize(t)

    def _finalize(self, t: Incoming):
        if not t.tmp.exists():
            t.tmp.touch()
        digest = storage.sha256_file(t.tmp)      # hash what is on disk, never trust the client
        if not security.safe_equal(digest, t.sha256):
            t.tmp.unlink(missing_ok=True)
            t.state, t.error, t.offset = "failed", "SHA-256 mismatch - file discarded", 0
            storage.add_history(_hist(t, "Failed (hash mismatch)", digest))
            return t
        dest = security.unique_path(storage.RECEIVED, t.name)
        t.tmp.replace(dest)
        t.state, t.final_name = "done", dest.name
        storage.add_history(_hist(t, "Completed", digest))
        return t

    def recent(self):
        return [t.public() for t in list(self.items.values())[-30:] if t.state in ("pending", "accepted", "receiving", "failed")]


def _hist(t, status, digest):
    return {"filename": t.final_name or t.name, "size": t.size, "direction": "Phone → Laptop", "device": t.device,
            "status": status, "sha256": digest, "duration": round(time.time() - t.started, 2)}
