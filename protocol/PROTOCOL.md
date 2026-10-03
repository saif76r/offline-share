# OfflineShare protocol v1

Transport: HTTP over the direct Wi-Fi Direct link (default port 8080). The link is WPA2-protected by Wi-Fi Direct itself,
and **the application adds its own authentication and encryption** (below), so nothing relies on the transport alone.
Reference implementations: `windows/server/crypto.py` (+ `windows/tests/devclient.py`), `android/.../security/Crypto.kt`.
Cross-language check: `protocol/test_vectors.json` (used by both the Python and Kotlin tests).

## 1. Pairing  `POST /pair`
Pairing secret `S` = the 6-digit PIN **or** the 128-bit QR secret. Both rotate after 120 s, after a successful pairing, or after 5 failed attempts.

Client → `{device_id, device_name, client_pub, proof}` (base64)
* `client_pub` = ephemeral ECDH P-256 public key, X9.62 uncompressed (65 bytes)
* `proof = HMAC-SHA256(key=S, "OSv1-client" ‖ device_id ‖ client_pub)` — S itself is never sent

Server verifies the proof, makes its own ephemeral key, and replies `{session_id, server_pub, server_proof, server_time, server_name}`.

```
shared   = ECDH(client_priv, server_pub)                (32 bytes)
okm      = HKDF-SHA256(ikm = shared ‖ S, salt = client_pub ‖ server_pub, info = "OSv1-keys", 64)
enc_key  = okm[0:32]      auth_key = okm[32:64]
server_proof = HMAC-SHA256(auth_key, "OSv1-server" ‖ session_id)     # phone verifies → mutual authentication
```
`server_time` lets the phone correct for clock differences (the devices have no internet time).

## 2. Request authentication (every endpoint except `/ping` and `/pair`)
Headers: `X-Session`, `X-Ts` (unix s), `X-Nonce` (random), `X-Sig`
```
X-Sig = hex(HMAC-SHA256(auth_key, session ‖ "\n" ‖ ts ‖ "\n" ‖ nonce ‖ "\n" ‖ METHOD ‖ "\n" ‖ path?query ‖ "\n" ‖ body_hash))
body_hash = hex SHA-256 of the JSON body (POST), or "" for GET and streamed PATCH
```
Rejected: unknown/expired session, bad signature, |now − ts| > 60 s, reused nonce (replay), tampered path/query.

## 3. File encryption
Files are split into 1 MiB chunks; each chunk is AES-256-GCM sealed.
```
file_key = HKDF-SHA256(enc_key, salt = none, info = "OSv1-file" ‖ file_id, 32)
nonce    = 12-byte big-endian chunk index        AAD = file_id ‖ 8-byte big-endian chunk index
frame    = uint32_be(len(ct)) ‖ ct               ct = ciphertext ‖ 16-byte tag
```
A key is unique per (session, file), so a nonce is never reused. Chunk index + AAD stop reordering/splicing. (File *names* travel in the signed control messages, not inside the encrypted stream.)

## 4. Phone → laptop
| Call | |
|---|---|
| `POST /upload/init {name,size,sha256}` | → `{id}`. Starts in state `pending`; the laptop user must press Accept |
| `GET /upload/<id>` | → `{state, offset, error}` — poll for acceptance; `offset` is the resume point (whole chunks only) |
| `PATCH /upload/<id>` + `Upload-Offset: N` | body = frames from chunk N/1 MiB. Server authenticates each chunk, appends, and at the end re-hashes the file on disk |

States: `pending → accepted → receiving → done` | `failed` (resumable) | `rejected`.
SHA-256 mismatch ⇒ file deleted and transfer reported failed — never reported as success.
**Resume:** after any drop, `GET /upload/<id>` → `offset`, then PATCH again from there.

## 5. Laptop → phone
| Call | |
|---|---|
| `GET /files` | → `{files:[{id,name,size,sha256}]}` (files queued in the laptop dashboard) |
| `GET /download/<id>?chunk=N` | streams frames from chunk N (`Content-Length` exact). Phone decrypts, verifies SHA-256, then saves |

The phone shows "Incoming Transfer · N files · size" with Reject / Accept All before downloading.

## 6. Other
`GET /ping` → `{app:"OfflineShare", v:1}` (unauthenticated; used to find the laptop's address).
Dashboard and `/api/*` are **loopback-only** on the laptop.

## 7. Phone as receiver
A phone in *Receive* mode runs the same server endpoints on port 8080 (`/ping`, `/pair`, `/upload/*`; `/files` is always empty).
It is the Wi-Fi Direct group owner, so the sender gets its IP from the P2P connection info. Pairing PIN is shown on the receiving phone;
incoming files wait for Accept/Reject. Wire format and crypto are identical to the laptop server.

## 8. Wi-Fi Direct bring-up
*Discover mode (default):* laptop advertises as a Wi-Fi Direct device, lists nearby phones (DeviceWatcher), connects with group-owner intent 15 so the phone learns the laptop IP from its P2P connection info, then the PIN pairing above runs.
*QR (legacy) mode:* laptop (Windows `WiFiDirectAdvertisementPublisher`, autonomous group owner, legacy settings) publishes SSID `DIRECT-OS-<host>` with a random passphrase.
QR JSON: `{"v":1,"n":host,"ip":[…],"p":8080,"s":ssid,"k":passphrase,"q":qr_secret}` — all temporary.
Phone: `WifiP2pConfig.Builder().setNetworkName(s).setPassphrase(k)` → `WifiP2pManager.connect()`; then probe `/ping` on each `ip`, then `/pair`.
