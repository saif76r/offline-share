package com.offlineshare.app.security

import okhttp3.Headers

/** An authenticated session with the laptop. Every request is HMAC-signed with a fresh nonce + timestamp. */
class Session(val id: String, val encKey: ByteArray, val authKey: ByteArray, val skewSec: Long, val baseUrl: String) {
    fun withBase(newBase: String) = Session(id, encKey, authKey, skewSec, newBase)   // laptop/phone IP changed

    /** [bodyHash] = SHA-256 hex of a JSON body; "" for GET and streaming PATCH (those bodies are AEAD-protected). */
    fun headers(method: String, target: String, bodyHash: String = ""): Headers {
        val ts = System.currentTimeMillis() / 1000 + skewSec
        val nonce = Crypto.randomHex(8)
        return Headers.Builder()
            .add("X-Session", id).add("X-Ts", ts.toString()).add("X-Nonce", nonce)
            .add("X-Sig", Crypto.signRequest(authKey, id, ts, nonce, method, target, bodyHash))
            .build()
    }
}
