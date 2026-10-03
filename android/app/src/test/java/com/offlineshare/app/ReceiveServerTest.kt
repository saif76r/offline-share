package com.offlineshare.app

import com.offlineshare.app.pairing.PairingClient
import com.offlineshare.app.pairing.PairingException
import com.offlineshare.app.security.Crypto
import com.offlineshare.app.transfer.ReceiveServer
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Random

/** End-to-end JVM test: Kotlin client crypto/pairing <-> Kotlin ReceiveServer (phone-to-phone path). */
class ReceiveServerTest {
    private lateinit var dir: File; private lateinit var out: File; private lateinit var srv: ReceiveServer
    private val http = OkHttpClient(); private val CH = Crypto.CHUNK
    private val results = mutableListOf<String>()

    @Before fun up() {
        dir = Files.createTempDirectory("osh").toFile(); out = File(dir, "out").apply { mkdirs() }
        srv = ReceiveServer(0, File(dir, "parts"), "Receiver", { f, n -> f.copyTo(File(out, n), true); f.delete(); n }, { results += it.status }, {})
        srv.start(10_000, true)
    }
    @After fun down() { srv.stop(); dir.deleteRecursively() }

    private fun base() = "http://127.0.0.1:${srv.listeningPort}"
    private fun pair(secret: String) = runBlocking { PairingClient.pair(http, base(), secret, "dev-1", "Sender") }

    @Test fun wrongPinRejected() { assertThrows(PairingException::class.java) { pair("000000".takeIf { srv.currentPin().first != "000000" } ?: "111111") } }

    @Test fun pairThenUploadWithResume() {
        val s = pair(srv.currentPin().first)
        val data = ByteArray(2 * CH + 777).also { Random(1).nextBytes(it) }
        val sha = Crypto.hex(MessageDigest.getInstance("SHA-256").digest(data))
        val initBody = JSONObject().put("name", "../../a.bin").put("size", data.size).put("sha256", sha).toString().toByteArray()
        val initReq = Request.Builder().url("${base()}/upload/init").headers(s.headers("POST", "/upload/init", Crypto.hex(Crypto.sha256(initBody))))
            .post(initBody.toRequestBody("application/json".toMediaType())).build()
        val id = http.newCall(initReq).execute().use { JSONObject(it.body!!.string()).getString("id") }

        fun patch(offset: Long, chunks: Int): Int {
            val key = Crypto.fileKey(s.encKey, id); val b = java.io.ByteArrayOutputStream()
            var i = (offset / CH).toInt(); var n = 0
            var pos = offset.toInt()
            while (pos < data.size && n < chunks) { val e = minOf(pos + CH, data.size); b.write(Crypto.sealFrame(key, id, i.toLong(), data.copyOfRange(pos, e))); pos = e; i++; n++ }
            val r = Request.Builder().url("${base()}/upload/$id").headers(s.headers("PATCH", "/upload/$id")).header("Upload-Offset", offset.toString())
                .patch(b.toByteArray().toRequestBody("application/octet-stream".toMediaType())).build()
            return http.newCall(r).execute().use { it.code }
        }
        assertEquals(403, patch(0, 1))                                  // not accepted yet
        srv.decide(id, true)
        assertEquals(422, patch(0, 1))                                  // "connection dropped" after 1 chunk
        val st = http.newCall(Request.Builder().url("${base()}/upload/$id").headers(s.headers("GET", "/upload/$id")).build()).execute().use { JSONObject(it.body!!.string()) }
        assertEquals(CH.toLong(), st.getLong("offset"))                 // resume point
        assertEquals(200, patch(st.getLong("offset"), 99))
        assertArrayEquals(data, File(out, "a.bin").readBytes())         // traversal name sanitised, content intact
        assertTrue(results.contains("Completed"))
    }

    @Test fun unauthenticatedBlocked() {
        http.newCall(Request.Builder().url("${base()}/files").build()).execute().use { assertEquals(401, it.code) }
    }
}
