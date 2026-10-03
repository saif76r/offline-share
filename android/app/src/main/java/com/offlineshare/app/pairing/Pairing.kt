package com.offlineshare.app.pairing

import com.offlineshare.app.security.Crypto
import com.offlineshare.app.security.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.Base64
import java.util.concurrent.TimeUnit

class PairingException(msg: String) : Exception(msg)

/** Contents of the laptop's QR code. Temporary: the secret and Wi-Fi passphrase rotate; nothing permanent is inside. */
data class QrPayload(val name: String, val ips: List<String>, val port: Int, val ssid: String, val passphrase: String, val secret: String) {
    companion object {
        fun parse(text: String): QrPayload? = try {
            val j = JSONObject(text)
            if (j.getInt("v") != 1) null else QrPayload(
                j.optString("n", "Laptop"), j.getJSONArray("ip").let { a -> (0 until a.length()).map { a.getString(it) } },
                j.getInt("p"), j.optString("s"), j.optString("k"), j.getString("q"))
        } catch (e: Exception) { null }
    }
}

object PairingClient {
    private val JSON = "application/json".toMediaType()
    private val b64e = Base64.getEncoder()
    private val b64d = Base64.getDecoder()

    /** First reachable "http://ip:port" among [ips] (probed in parallel; short timeout). */
    suspend fun findServer(client: OkHttpClient, ips: List<String>, port: Int): String? = coroutineScope {
        val quick = client.newBuilder().connectTimeout(2, TimeUnit.SECONDS).readTimeout(2, TimeUnit.SECONDS).build()
        ips.distinct().map { ip ->
            async(Dispatchers.IO) {
                val base = "http://$ip:$port"
                try {
                    quick.newCall(Request.Builder().url("$base/ping").build()).execute().use { r ->
                        if (r.isSuccessful && r.body?.string()?.contains("OfflineShare") == true) base else null
                    }
                } catch (e: Exception) { null }
            }
        }.awaitAll().firstOrNull { it != null }
    }

    /** [secret] is the typed PIN or the QR secret. It is never transmitted - only an HMAC proof of it. */
    suspend fun pair(client: OkHttpClient, base: String, secret: String, deviceId: String, deviceName: String): Session =
        withContext(Dispatchers.IO) {
            val kp = Crypto.newKeyPair()
            val cpub = Crypto.pubBytes(kp.public)
            val body = JSONObject()
                .put("device_id", deviceId).put("device_name", deviceName)
                .put("client_pub", b64e.encodeToString(cpub))
                .put("proof", b64e.encodeToString(Crypto.clientProof(secret, deviceId, cpub)))
                .toString().toRequestBody(JSON)
            client.newCall(Request.Builder().url("$base/pair").post(body).build()).execute().use { r ->
                val j = JSONObject(r.body?.string().orEmpty().ifBlank { "{}" })
                if (!r.isSuccessful) throw PairingException(j.optString("error", "Pairing failed (${r.code})"))
                val spub = b64d.decode(j.getString("server_pub"))
                val (enc, auth) = Crypto.deriveSessionKeys(Crypto.ecdh(kp.private, spub), secret, cpub, spub)
                val sid = j.getString("session_id")
                if (!java.security.MessageDigest.isEqual(b64d.decode(j.getString("server_proof")), Crypto.serverProof(auth, sid)))
                    throw PairingException("Laptop failed to prove the PIN - possible impostor. Pairing aborted.")
                Session(sid, enc, auth, j.getLong("server_time") - System.currentTimeMillis() / 1000, base)
            }
        }
}
