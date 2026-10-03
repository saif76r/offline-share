package com.offlineshare.app.security

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Protocol v1 crypto. Must stay byte-compatible with windows/server/crypto.py (see protocol/test_vectors.json). */
object Crypto {
    const val CHUNK = 1 shl 20
    const val TAG = 16
    const val OVERHEAD = 4 + TAG
    private val rng = SecureRandom()
    private val SPKI_P256 = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

    fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    fun randomHex(n: Int) = hex(ByteArray(n).also { rng.nextBytes(it) })
    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(key, "HmacSHA256"))
        return m.doFinal(msg)
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray, len: Int): ByteArray {
        val prk = hmac(salt ?: ByteArray(32), ikm)
        var t = ByteArray(0)
        val out = java.io.ByteArrayOutputStream()
        var i = 1
        while (out.size() < len) {
            t = hmac(prk, t + info + byteArrayOf(i.toByte()))
            out.write(t); i++
        }
        return out.toByteArray().copyOf(len)
    }

    fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun fixed32(v: BigInteger): ByteArray {
        val a = v.toByteArray(); val n = minOf(32, a.size)
        return ByteArray(32).also { System.arraycopy(a, a.size - n, it, 32 - n, n) }
    }

    /** X9.62 uncompressed point (65 bytes) - same as Python's public_bytes(X962, UncompressedPoint). */
    fun pubBytes(pub: PublicKey): ByteArray {
        val w = (pub as ECPublicKey).w
        return byteArrayOf(4) + fixed32(w.affineX) + fixed32(w.affineY)
    }

    fun ecdh(priv: PrivateKey, peerPub: ByteArray): ByteArray {
        require(peerPub.size == 65 && peerPub[0].toInt() == 4) { "bad public key" }
        val pk = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(SPKI_P256 + peerPub))
        return KeyAgreement.getInstance("ECDH").run { init(priv); doPhase(pk, true); generateSecret() }
    }

    /** Returns (encKey, authKey). */
    fun deriveSessionKeys(shared: ByteArray, secret: String, clientPub: ByteArray, serverPub: ByteArray): Pair<ByteArray, ByteArray> {
        val okm = hkdf(shared + secret.toByteArray(), clientPub + serverPub, "OSv1-keys".toByteArray(), 64)
        return okm.copyOfRange(0, 32) to okm.copyOfRange(32, 64)
    }

    fun clientProof(secret: String, deviceId: String, clientPub: ByteArray) =
        hmac(secret.toByteArray(), "OSv1-client".toByteArray() + deviceId.toByteArray() + clientPub)

    fun serverProof(authKey: ByteArray, sessionId: String) = hmac(authKey, "OSv1-server".toByteArray() + sessionId.toByteArray())

    fun signRequest(authKey: ByteArray, sid: String, ts: Long, nonce: String, method: String, target: String, bodyHash: String) =
        hex(hmac(authKey, "$sid\n$ts\n$nonce\n$method\n$target\n$bodyHash".toByteArray()))

    fun fileKey(encKey: ByteArray, fileId: String) = hkdf(encKey, null, "OSv1-file".toByteArray() + fileId.toByteArray(), 32)

    private fun nonce(i: Long) = ByteBuffer.allocate(12).putLong(4, i).array()
    private fun aad(fileId: String, i: Long) = fileId.toByteArray() + ByteBuffer.allocate(8).putLong(i).array()

    /** length-prefixed AES-256-GCM frame for chunk [i]. */
    fun sealFrame(key: ByteArray, fileId: String, i: Long, plain: ByteArray, len: Int = plain.size): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce(i)))
        c.updateAAD(aad(fileId, i))
        val ct = c.doFinal(plain, 0, len)
        return ByteBuffer.allocate(4 + ct.size).putInt(ct.size).put(ct).array()
    }

    fun openFrame(key: ByteArray, fileId: String, i: Long, ct: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce(i)))
        c.updateAAD(aad(fileId, i))
        return c.doFinal(ct)       // throws AEADBadTagException when tampered
    }

    fun encryptedLength(plainRemaining: Long): Long {
        val chunks = (plainRemaining + CHUNK - 1) / CHUNK
        return plainRemaining + chunks * OVERHEAD
    }
}
