"""OfflineShare crypto (protocol v1). Mirrored byte-for-byte by android/.../security/Crypto.kt.

Pairing : ECDH P-256 (ephemeral) + shared pairing secret (PIN or QR secret) mixed into HKDF-SHA256.
          Client proves knowledge of the secret with HMAC; server proves with an HMAC under the derived key.
Requests: HMAC-SHA256 signature over session|timestamp|nonce|method|target|body-hash.
Files   : AES-256-GCM, 1 MiB chunks, per-file key (HKDF), nonce = chunk index, AAD = file id + chunk index.
Frame   : 4-byte big-endian length || ciphertext||tag.
"""
import hashlib, hmac
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK = 1 << 20
TAG = 16
FRAME_OVERHEAD = 4 + TAG


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def new_keypair():
    return ec.generate_private_key(ec.SECP256R1())


def pub_bytes(priv) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def ecdh(priv, peer_pub: bytes) -> bytes:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)  # raises on invalid point
    return priv.exchange(ec.ECDH(), peer)


def derive_session_keys(shared: bytes, secret: str, client_pub: bytes, server_pub: bytes):
    okm = HKDF(hashes.SHA256(), 64, client_pub + server_pub, b"OSv1-keys").derive(shared + secret.encode())
    return okm[:32], okm[32:]          # enc_key, auth_key


def client_proof(secret: str, device_id: str, client_pub: bytes) -> bytes:
    return hmac_sha256(secret.encode(), b"OSv1-client" + device_id.encode() + client_pub)


def server_proof(auth_key: bytes, session_id: str) -> bytes:
    return hmac_sha256(auth_key, b"OSv1-server" + session_id.encode())


def sign_request(auth_key: bytes, sid: str, ts: int, nonce: str, method: str, target: str, body_hash: str) -> str:
    return hmac_sha256(auth_key, f"{sid}\n{ts}\n{nonce}\n{method}\n{target}\n{body_hash}".encode()).hex()


def file_key(enc_key: bytes, file_id: str) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, b"OSv1-file" + file_id.encode()).derive(enc_key)


def _aad(file_id: str, i: int) -> bytes:
    return file_id.encode() + i.to_bytes(8, "big")


def seal(key: bytes, file_id: str, i: int, plain: bytes) -> bytes:
    ct = AESGCM(key).encrypt(i.to_bytes(12, "big"), plain, _aad(file_id, i))
    return len(ct).to_bytes(4, "big") + ct


def open_frame(key: bytes, file_id: str, i: int, ct: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(i.to_bytes(12, "big"), ct, _aad(file_id, i))
    except InvalidTag:
        raise ValueError("authentication failed (corrupt or tampered data)")


def read_exact(stream, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        b = stream.read(n - len(buf))
        if not b:
            break
        buf += b
    return bytes(buf)


def read_frame(stream):
    """Next ciphertext, or None at clean EOF. Raises EOFError if the stream stops mid-frame."""
    hdr = read_exact(stream, 4)
    if not hdr:
        return None
    if len(hdr) < 4:
        raise EOFError("truncated frame header")
    n = int.from_bytes(hdr, "big")
    if n < TAG or n > CHUNK + TAG:
        raise ValueError("invalid frame length")
    ct = read_exact(stream, n)
    if len(ct) < n:
        raise EOFError("truncated frame")
    return ct


def encrypted_length(plain_remaining: int) -> int:
    chunks = -(-plain_remaining // CHUNK)
    return plain_remaining + chunks * FRAME_OVERHEAD


def encrypt_file(path, key: bytes, file_id: str, start_chunk: int = 0):
    with open(path, "rb") as f:
        f.seek(start_chunk * CHUNK)
        i = start_chunk
        while chunk := f.read(CHUNK):
            yield seal(key, file_id, i, chunk)
            i += 1
