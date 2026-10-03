package com.offlineshare.app

import com.offlineshare.app.security.Crypto
import com.offlineshare.app.storage.Names
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest

/** Verifies the Kotlin crypto is byte-compatible with the Python server using protocol/test_vectors.json. */
class CryptoTest {
    private val v = JSONObject(javaClass.classLoader!!.getResource("test_vectors.json")!!.readText())
    private fun h(k: String) = Crypto.unhex(v.getString(k))

    @Test fun sessionKeys() {
        val (enc, auth) = Crypto.deriveSessionKeys(h("shared"), v.getString("secret"), h("client_pub"), h("server_pub"))
        assertEquals(v.getString("enc_key"), Crypto.hex(enc)); assertEquals(v.getString("auth_key"), Crypto.hex(auth))
    }
    @Test fun proofsAndSignature() {
        assertEquals(v.getString("client_proof"), Crypto.hex(Crypto.clientProof(v.getString("secret"), v.getString("device_id"), h("client_pub"))))
        assertEquals(v.getString("server_proof"), Crypto.hex(Crypto.serverProof(h("auth_key"), "abc123")))
        val body = Crypto.hex(MessageDigest.getInstance("SHA-256").digest("{}".toByteArray()))
        assertEquals(v.getString("sig"), Crypto.signRequest(h("auth_key"), "abc123", 1700000000, "n0nc3", "POST", "/upload/init", body))
    }
    @Test fun fileKeyAndFrame() {
        val fk = Crypto.fileKey(h("enc_key"), v.getString("file_id"))
        assertEquals(v.getString("file_key"), Crypto.hex(fk))
        val frame = Crypto.sealFrame(fk, v.getString("file_id"), 3, h("plain"))
        assertEquals(v.getString("frame_index3"), Crypto.hex(frame))
        assertArrayEquals(h("plain"), Crypto.openFrame(fk, v.getString("file_id"), 3, frame.copyOfRange(4, frame.size)))
    }
    @Test(expected = java.security.GeneralSecurityException::class) fun tamperDetected() {
        val fk = h("file_key"); val f = Crypto.sealFrame(fk, "x", 0, byteArrayOf(1, 2, 3)); f[6] = (f[6].toInt() xor 1).toByte()
        Crypto.openFrame(fk, "x", 0, f.copyOfRange(4, f.size))
    }
    @Test fun ecdhAgrees() {
        val a = Crypto.newKeyPair(); val b = Crypto.newKeyPair()
        assertEquals(65, Crypto.pubBytes(a.public).size)
        assertArrayEquals(Crypto.ecdh(a.private, Crypto.pubBytes(b.public)), Crypto.ecdh(b.private, Crypto.pubBytes(a.public)))
    }
    @Test fun sanitize() {
        assertEquals("file", Names.sanitize("../../Windows/System32/file")); assertEquals("_CON", Names.sanitize("CON"))
        assertEquals("résumé 文件.pdf", Names.sanitize("résumé 文件.pdf"))
    }
    @Test fun uniqueNames() {
        val taken = setOf("d.pdf", "d (1).pdf")
        assertEquals("d (2).pdf", Names.unique("d.pdf") { it in taken })
    }
}
