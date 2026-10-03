"""Security helpers: filename sanitising, safe paths, tokens."""
import hmac, os, re, secrets, unicodedata
from pathlib import Path

MAX_NAME_LEN = 150
_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def sanitize_filename(name: str) -> str:
    """Strip directories, control chars and Windows-reserved names. Never returns ''."""
    name = unicodedata.normalize("NFC", str(name or ""))
    name = name.replace("\\", "/").split("/")[-1]
    name = _BAD.sub("_", name).strip(" .")
    if not name:
        name = "file"
    stem, dot, _ = name.rpartition(".")
    base = stem if dot else name
    if base.upper() in _RESERVED:
        name = "_" + name
    if len(name) > MAX_NAME_LEN:
        root, ext = os.path.splitext(name)
        name = root[: MAX_NAME_LEN - len(ext)] + ext
    return name


def unique_path(directory: Path, name: str) -> Path:
    """Never overwrite: document.pdf -> document (1).pdf -> document (2).pdf"""
    directory = Path(directory)
    candidate = directory / name
    root, ext = os.path.splitext(name)
    i = 1
    while candidate.exists():
        candidate = directory / f"{root} ({i}){ext}"
        i += 1
    return candidate


def ensure_inside(base: Path, target: Path) -> Path:
    base, target = Path(base).resolve(), Path(target).resolve()
    if base != target and base not in target.parents:
        raise ValueError("path escapes storage directory")
    return target


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_pin() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def safe_equal_bytes(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
