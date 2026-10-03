package com.offlineshare.app.transfer

import android.content.Context
import android.net.Uri
import com.offlineshare.app.security.Crypto
import com.offlineshare.app.security.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.security.MessageDigest

class TransferException(msg: String, val resumable: Boolean = false) : Exception(msg)
data class RemoteFile(val id: String, val name: String, val size: Long, val sha256: String)

/** Talks the OfflineShare protocol (see protocol/PROTOCOL.md). */
class TransferClient(private val http: OkHttpClient, private val session: Session) {
    private val base = session.baseUrl
    private val JSON = "application/json".toMediaType()
    private val BIN = "application/octet-stream".toMediaType()

    private fun signedGet(target: String) = Request.Builder().url(base + target).headers(session.headers("GET", target)).build()

    suspend fun listFiles(): List<RemoteFile> = withContext(Dispatchers.IO) {
        http.newCall(signedGet("/files")).execute().use { r ->
            if (!r.isSuccessful) throw TransferException("Laptop refused (${r.code}). Pair again.")
            val a = JSONObject(r.body!!.string()).getJSONArray("files")
            (0 until a.length()).map { a.getJSONObject(it).let { j -> RemoteFile(j.getString("id"), j.getString("name"), j.getLong("size"), j.getString("sha256")) } }
        }
    }

    // ------------------------------------------------------------------ phone -> laptop
    /** SHA-256 of a content Uri, streamed. */
    suspend fun hashUri(ctx: Context, uri: Uri, onBytes: (Long) -> Unit = {}): String = withContext(Dispatchers.IO) {
        val md = MessageDigest.getInstance("SHA-256"); val buf = ByteArray(1 shl 16); var total = 0L
        ctx.contentResolver.openInputStream(uri)!!.use { ins ->
            while (true) { val n = ins.read(buf); if (n < 0) break; md.update(buf, 0, n); total += n; onBytes(total); currentCoroutineContext().ensureActive() }
        }
        Crypto.hex(md.digest())
    }

    /** Creates the upload on the laptop (user must Accept there). Returns the server-side transfer id. */
    suspend fun initUpload(name: String, size: Long, sha256: String): String = withContext(Dispatchers.IO) {
        val bytes = JSONObject().put("name", name).put("size", size).put("sha256", sha256).toString().toByteArray()
        val hash = Crypto.hex(Crypto.sha256(bytes))
        val req = Request.Builder().url("$base/upload/init").headers(session.headers("POST", "/upload/init", hash))
            .post(bytes.toRequestBody(JSON)).build()
        http.newCall(req).execute().use { r ->
            val j = JSONObject(r.body?.string().orEmpty().ifBlank { "{}" })
            if (!r.isSuccessful) throw TransferException(j.optString("error", "Laptop refused the file"))
            j.getString("id")
        }
    }

    private data class Status(val state: String, val offset: Long, val error: String)
    private suspend fun status(id: String): Status = withContext(Dispatchers.IO) {
        http.newCall(signedGet("/upload/$id")).execute().use { r ->
            if (!r.isSuccessful) throw TransferException("Transfer unknown to laptop (${r.code})")
            JSONObject(r.body!!.string()).let { Status(it.getString("state"), it.getLong("offset"), it.optString("error")) }
        }
    }

    /** Waits for the user to tap Accept on the laptop. */
    suspend fun awaitAccepted(id: String, timeoutMs: Long = 5 * 60_000L) {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            when (status(id).state) {
                "accepted", "receiving", "failed" -> return
                "rejected" -> throw TransferException("Rejected on the laptop")
                "done" -> return
            }
            delay(800)
        }
        throw TransferException("Laptop did not respond - nothing was sent")
    }

    /** Streams the encrypted file from the server's resume point. Safe to call again after any interruption. */
    suspend fun upload(ctx: Context, uri: Uri, id: String, size: Long, onBytes: (Long) -> Unit) {
        val st = status(id)
        if (st.state == "done") { onBytes(size); return }
        val offset = st.offset
        onBytes(offset)
        val body = object : RequestBody() {
            override fun contentType() = BIN
            override fun contentLength() = Crypto.encryptedLength(size - offset)
            override fun writeTo(sink: BufferedSink) {
                val key = Crypto.fileKey(session.encKey, id)
                ctx.contentResolver.openInputStream(uri)!!.use { ins ->
                    skipFully(ins, offset)
                    var sent = offset; var idx = offset / Crypto.CHUNK; val buf = ByteArray(Crypto.CHUNK)
                    while (sent < size) {
                        val want = minOf(Crypto.CHUNK.toLong(), size - sent).toInt()
                        val n = readFully(ins, buf, want)
                        if (n < want) throw IOException("File changed while sending")
                        sink.write(Crypto.sealFrame(key, id, idx, buf, n)); sink.flush()
                        sent += n; idx++; onBytes(sent)
                    }
                }
            }
        }
        val req = Request.Builder().url("$base/upload/$id").headers(session.headers("PATCH", "/upload/$id"))
            .header("Upload-Offset", offset.toString()).patch(body).build()
        try {
            withContext(Dispatchers.IO) {
                http.newCall(req).execute().use { r ->
                    val j = JSONObject(r.body?.string().orEmpty().ifBlank { "{}" })
                    if (r.isSuccessful && j.optString("state") == "done") return@use
                    val err = j.optString("error", "HTTP ${r.code}")
                    throw TransferException(err, resumable = !err.contains("SHA-256"))
                }
            }
        } catch (e: IOException) { throw TransferException("Connection lost. Your file is safe - you can resume.", true) }
    }

    // ------------------------------------------------------------------ laptop -> phone
    /** Downloads + decrypts into [part] (resumes from existing bytes), then verifies SHA-256. */
    suspend fun download(file: RemoteFile, part: File, onBytes: (Long) -> Unit) = withContext(Dispatchers.IO) {
        val startChunk = part.length() / Crypto.CHUNK
        RandomAccessFile(part, "rw").use { it.setLength(startChunk * Crypto.CHUNK) }   // drop any partial chunk
        onBytes(startChunk * Crypto.CHUNK)
        val target = "/download/${file.id}?chunk=$startChunk"
        try {
            http.newCall(signedGet(target)).execute().use { r ->
                if (!r.isSuccessful) throw TransferException("Laptop refused download (${r.code})")
                val src = r.body!!.source(); val key = Crypto.fileKey(session.encKey, file.id)
                var idx = startChunk; var got = startChunk * Crypto.CHUNK
                java.io.FileOutputStream(part, true).use { out ->
                    while (!src.exhausted()) {
                        currentCoroutineContext().ensureActive()
                        val len = src.readInt()
                        if (len < Crypto.TAG || len > Crypto.CHUNK + Crypto.TAG) throw TransferException("Corrupt data from laptop")
                        val plain = try { Crypto.openFrame(key, file.id, idx, src.readByteArray(len.toLong())) }
                            catch (e: java.security.GeneralSecurityException) { throw TransferException("Data failed authentication - discarded") }
                        out.write(plain); got += plain.size; idx++; onBytes(got)
                    }
                }
            }
        } catch (e: IOException) { throw TransferException("Connection lost. Your file is safe - you can resume.", true) }
        if (part.length() != file.size) throw TransferException("Connection lost. Your file is safe - you can resume.", true)
        val md = MessageDigest.getInstance("SHA-256"); val buf = ByteArray(1 shl 16)
        part.inputStream().use { ins -> while (true) { val n = ins.read(buf); if (n < 0) break; md.update(buf, 0, n) } }
        if (Crypto.hex(md.digest()) != file.sha256) { part.delete(); throw TransferException("SHA-256 mismatch - file discarded") }
    }

    private fun skipFully(ins: InputStream, n: Long) { var left = n; while (left > 0) { val s = ins.skip(left); if (s <= 0) { if (ins.read() < 0) break else left-- } else left -= s } }
    private fun readFully(ins: InputStream, buf: ByteArray, len: Int): Int { var r = 0; while (r < len) { val n = ins.read(buf, r, len - r); if (n < 0) break; r += n }; return r }
}

/** Moving-average speed + ETA for the progress UI. */
class SpeedMeter(private val total: Long) {
    private val t0 = System.currentTimeMillis(); private var base = -1L
    fun update(done: Long): Pair<Long, Long> {            // (bytes/sec, eta seconds)
        if (base < 0) base = done
        val secs = maxOf(0.001, (System.currentTimeMillis() - t0) / 1000.0)
        val bps = ((done - base) / secs).toLong()
        return bps to (if (bps > 0) (total - done) / bps else -1)
    }
}
