package com.offlineshare.app.transfer

import com.offlineshare.app.security.Crypto
import com.offlineshare.app.storage.HistoryItem
import com.offlineshare.app.storage.Names
import fi.iki.elonen.NanoHTTPD
import org.json.JSONObject
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs

/**
 * Phone-side server so ANOTHER phone running OfflineShare can send files to this one (receive mode).
 * Speaks the same protocol as the Windows server (protocol/PROTOCOL.md): PIN pairing, signed requests, AES-256-GCM chunks,
 * explicit Accept/Reject, resume and SHA-256 verification.
 */
class ReceiveServer(
    port: Int,
    private val partDir: File,
    private val deviceName: String,
    private val publish: (File, String) -> String,        // moves a verified file into Downloads, returns final name
    private val onDone: (HistoryItem) -> Unit,
    private val onChange: () -> Unit,
) : NanoHTTPD(port) {

    class Incoming(val id: String, val name: String, val size: Long, val sha: String, val device: String, val deviceId: String, partDir: File) {
        @Volatile var state = "pending"      // pending|accepted|rejected|receiving|done|failed
        @Volatile var offset = 0L
        @Volatile var error = ""
        @Volatile var finalName = ""
        val tmp = File(partDir, "$id.part")
        val startedAt = System.currentTimeMillis()
    }

    private class SSession(val id: String, val deviceId: String, val name: String, val enc: ByteArray, val auth: ByteArray, val created: Long = System.currentTimeMillis())

    private val rnd = SecureRandom()
    private val b64e = Base64.getEncoder(); private val b64d = Base64.getDecoder()
    private val sessions = ConcurrentHashMap<String, SSession>()
    private val seen = ConcurrentHashMap<String, Long>()
    val incoming = ConcurrentHashMap<String, Incoming>()

    @Volatile private var pin = newPin()
    @Volatile private var pinExpires = System.currentTimeMillis() + PIN_TTL_MS
    private var attempts = 0

    companion object {
        const val PIN_TTL_MS = 120_000L; const val MAX_ATTEMPTS = 5; const val SKEW_S = 60L
        const val MAX_FILE = 20L * 1024 * 1024 * 1024
    }

    private fun newPin() = "%06d".format(rnd.nextInt(1_000_000))
    private fun rotate() { pin = newPin(); pinExpires = System.currentTimeMillis() + PIN_TTL_MS; attempts = 0 }

    /** (PIN, seconds until it rotates). */
    @Synchronized fun currentPin(): Pair<String, Int> {
        if (System.currentTimeMillis() > pinExpires) rotate()
        return pin to ((pinExpires - System.currentTimeMillis()) / 1000).toInt()
    }

    fun decide(id: String, accept: Boolean) { incoming[id]?.let { if (it.state == "pending") it.state = if (accept) "accepted" else "rejected"; onChange() } }
    fun pairedDevices() = sessions.values.map { it.name }

    // ------------------------------------------------------------------ HTTP plumbing
    private fun status(code: Int) = object : Response.IStatus {
        override fun getRequestStatus() = code
        override fun getDescription() = "$code"
    }
    private fun json(code: Int, o: JSONObject) = newFixedLengthResponse(status(code), "application/json", o.toString())
    private fun err(code: Int, msg: String) = json(code, JSONObject().put("error", msg))

    private fun readBody(s: IHTTPSession, max: Int = 65536): ByteArray {
        val len = s.headers["content-length"]?.toIntOrNull() ?: 0
        require(len in 0..max) { "body too large" }
        val buf = ByteArray(len); var r = 0
        while (r < len) { val n = s.inputStream.read(buf, r, len - r); if (n < 0) break; r += n }
        return buf.copyOf(r)
    }

    override fun serve(s: IHTTPSession): Response = try {
        val path = s.uri
        when {
            s.method == Method.GET && path == "/ping" -> json(200, JSONObject().put("app", "OfflineShare").put("v", 1))
            s.method == Method.POST && path == "/pair" -> pair(s)
            else -> {
                val body = if (s.method == Method.POST) readBody(s) else null
                val sess = verify(s, body)
                if (sess == null) err(401, "unauthorized") else routeAuthed(sess, s, path, body)
            }
        }
    } catch (e: IllegalArgumentException) { err(400, e.message ?: "bad request") }
    catch (e: Exception) { err(500, "server error") }

    private fun routeAuthed(sess: SSession, s: IHTTPSession, path: String, body: ByteArray?): Response {
        val parts = path.trim('/').split('/')
        return when {
            s.method == Method.GET && path == "/files" -> json(200, JSONObject().put("files", org.json.JSONArray()))   // phones receive only
            s.method == Method.POST && path == "/upload/init" -> uploadInit(sess, JSONObject(String(body ?: ByteArray(0))))
            parts.size == 2 && parts[0] == "upload" && s.method == Method.GET -> uploadStatus(sess, parts[1])
            parts.size == 2 && parts[0] == "upload" && s.method == Method.PATCH -> uploadChunk(sess, s, parts[1])
            else -> err(404, "not found")
        }
    }

    // ------------------------------------------------------------------ pairing + auth
    private fun pair(s: IHTTPSession): Response {
        val j = JSONObject(String(readBody(s)))
        val deviceId = j.optString("device_id").take(64); val name = j.optString("device_name", "Phone").take(64).ifBlank { "Phone" }
        val cpub = try { b64d.decode(j.getString("client_pub")) } catch (e: Exception) { return err(400, "malformed pairing request") }
        val proof = try { b64d.decode(j.getString("proof")) } catch (e: Exception) { return err(400, "malformed pairing request") }
        if (deviceId.isEmpty() || cpub.size != 65) return err(400, "malformed pairing request")
        synchronized(this) {
            if (System.currentTimeMillis() > pinExpires) { rotate(); return err(403, "PIN expired") }
            if (++attempts > MAX_ATTEMPTS) { rotate(); return err(403, "Too many attempts; new PIN generated") }
            if (!MessageDigest.isEqual(Crypto.clientProof(pin, deviceId, cpub), proof)) return err(403, "Invalid PIN")
            val kp = Crypto.newKeyPair(); val spub = Crypto.pubBytes(kp.public)
            val (enc, auth) = try { Crypto.deriveSessionKeys(Crypto.ecdh(kp.private, cpub), pin, cpub, spub) } catch (e: Exception) { return err(400, "malformed pairing request") }
            val sid = Crypto.randomHex(16)
            sessions.values.removeAll { it.deviceId == deviceId }
            sessions[sid] = SSession(sid, deviceId, name, enc, auth)
            rotate(); onChange()
            return json(200, JSONObject().put("session_id", sid).put("server_pub", b64e.encodeToString(spub))
                .put("server_proof", b64e.encodeToString(Crypto.serverProof(auth, sid))).put("server_name", deviceName)
                .put("server_time", System.currentTimeMillis() / 1000))
        }
    }

    private fun verify(s: IHTTPSession, body: ByteArray?): SSession? {
        val h = s.headers
        val sid = h["x-session"] ?: return null; val ts = h["x-ts"]?.toLongOrNull() ?: return null
        val nonce = h["x-nonce"]?.takeIf { it.length in 1..64 } ?: return null; val sig = h["x-sig"] ?: return null
        val sess = sessions[sid] ?: return null
        val now = System.currentTimeMillis()
        if (abs(now / 1000 - ts) > SKEW_S || now - sess.created > 12 * 3600_000L) return null
        val q = s.queryParameterString?.takeIf { it.isNotEmpty() }?.let { "?$it" } ?: ""
        val bodyHash = if (s.method == Method.GET || s.method == Method.PATCH) "" else Crypto.hex(Crypto.sha256(body ?: ByteArray(0)))
        val expect = Crypto.signRequest(sess.auth, sid, ts, nonce, s.method.name, s.uri + q, bodyHash)
        if (!MessageDigest.isEqual(expect.toByteArray(), sig.toByteArray())) return null
        seen.entries.removeIf { now - it.value > 2 * SKEW_S * 1000 }
        if (seen.putIfAbsent(sid + nonce, now) != null) return null          // replay
        return sess
    }

    // ------------------------------------------------------------------ uploads
    private fun uploadInit(sess: SSession, j: JSONObject): Response {
        val size = j.optLong("size", -1); val sha = j.optString("sha256").lowercase()
        if (size < 0 || size > MAX_FILE) return err(400, "invalid or oversized file")
        if (sha.length != 64 || !sha.all { it in "0123456789abcdef" }) return err(400, "invalid sha256")
        val t = Incoming(Crypto.randomHex(16), Names.sanitize(j.optString("name")), size, sha, sess.name, sess.deviceId, partDir.apply { mkdirs() })
        incoming[t.id] = t; onChange()
        return json(200, JSONObject().put("id", t.id).put("state", t.state))
    }

    private fun mine(sess: SSession, id: String) = incoming[id]?.takeIf { it.deviceId == sess.deviceId }

    /** Bytes safely stored: whole chunks only (a partial chunk is discarded). */
    private fun resumeOffset(t: Incoming): Long {
        if (t.state == "done") return t.size
        val have = if (t.tmp.exists()) t.tmp.length() else 0L
        val safe = have / Crypto.CHUNK * Crypto.CHUNK
        if (safe != have) RandomAccessFile(t.tmp, "rw").use { it.setLength(safe) }
        return safe
    }

    private fun uploadStatus(sess: SSession, id: String): Response {
        val t = mine(sess, id) ?: return err(404, "unknown transfer")
        return json(200, JSONObject().put("state", t.state).put("offset", resumeOffset(t)).put("error", t.error).put("final_name", t.finalName))
    }

    private class Bounded(private val src: InputStream, private var left: Long) : InputStream() {
        override fun read(): Int { if (left <= 0) return -1; val b = src.read(); if (b >= 0) left--; return b }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (left <= 0) return -1
            val n = src.read(b, off, minOf(len.toLong(), left).toInt()); if (n > 0) left -= n; return n
        }
    }
    private fun readN(ins: InputStream, n: Int): ByteArray? {
        val b = ByteArray(n); var r = 0
        while (r < n) { val k = ins.read(b, r, n - r); if (k < 0) { if (r == 0) return null else throw EOFException() }; r += k }
        return b
    }

    private fun uploadChunk(sess: SSession, s: IHTTPSession, id: String): Response {
        fun closing(r: Response) = r.also { it.closeConnection(true) }      // body may be unread -> don't reuse the connection
        val t = mine(sess, id) ?: return closing(err(404, "unknown transfer"))
        val off = s.headers["upload-offset"]?.toLongOrNull() ?: return closing(err(400, "bad offset"))
        if (t.state !in setOf("accepted", "receiving", "failed")) return closing(err(403, "transfer is ${t.state}"))
        val have = resumeOffset(t)
        if (off != have) return closing(err(409, "offset mismatch; server has $have"))
        val len = s.headers["content-length"]?.toLongOrNull() ?: return closing(err(400, "length required"))
        val ins = Bounded(s.inputStream, len)
        t.state = "receiving"; t.offset = have; t.error = ""
        val key = Crypto.fileKey(sess.enc, t.id); var idx = have / Crypto.CHUNK
        try {
            FileOutputStream(t.tmp, true).use { out ->
                while (t.offset < t.size) {
                    val hdr = readN(ins, 4) ?: break
                    val n = ByteBuffer.wrap(hdr).int
                    if (n < Crypto.TAG || n > Crypto.CHUNK + Crypto.TAG) { t.state = "failed"; t.error = "invalid frame length"; return closing(err(409, t.error)) }
                    val ct = readN(ins, n) ?: throw EOFException()
                    if (ct.size != minOf(Crypto.CHUNK.toLong(), t.size - t.offset).toInt() + Crypto.TAG) { t.state = "failed"; t.error = "unexpected chunk size"; return closing(err(409, t.error)) }
                    val plain = try { Crypto.openFrame(key, t.id, idx, ct) }
                        catch (e: GeneralSecurityException) { t.state = "failed"; t.error = "authentication failed (corrupt or tampered data)"; return closing(err(409, t.error)) }
                    out.write(plain); t.offset += plain.size; idx++; onChange()
                }
            }
        } catch (e: IOException) { t.state = "failed"; t.error = "interrupted - resume available"; onChange(); return closing(reply(t, 422)) }
        if (t.offset < t.size) { t.state = "failed"; t.error = "interrupted - resume available"; onChange(); return closing(reply(t, 422)) }
        return finalizeUpload(t)
    }

    private fun reply(t: Incoming, code: Int) = json(code, JSONObject().put("state", t.state).put("offset", t.offset).put("error", t.error).put("final_name", t.finalName))

    private fun finalizeUpload(t: Incoming): Response {
        if (!t.tmp.exists()) t.tmp.createNewFile()
        val md = MessageDigest.getInstance("SHA-256"); val buf = ByteArray(1 shl 16)
        t.tmp.inputStream().use { i -> while (true) { val n = i.read(buf); if (n < 0) break; md.update(buf, 0, n) } }
        val digest = Crypto.hex(md.digest())                                // hash what is on disk, never trust the sender
        val ms = System.currentTimeMillis() - t.startedAt
        if (digest != t.sha) {
            t.tmp.delete(); t.state = "failed"; t.error = "SHA-256 mismatch - file discarded"; t.offset = 0; onChange()
            onDone(HistoryItem(t.name, t.size, "Phone → Phone", t.device, "Failed (hash mismatch)", digest, System.currentTimeMillis(), ms))
            return reply(t, 422)
        }
        t.finalName = publish(t.tmp, t.name); t.state = "done"; t.offset = t.size; onChange()
        onDone(HistoryItem(t.finalName, t.size, "Phone → Phone", t.device, "Completed", digest, System.currentTimeMillis(), ms))
        return reply(t, 200)
    }
}
