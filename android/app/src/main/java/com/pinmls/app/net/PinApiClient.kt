package com.pinmls.app.net

import android.util.Base64
import com.pinmls.app.BuildConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import uniffi.pin_mobile_ffi.PinMobileClient
import uniffi.pin_mobile_ffi.mobileSolvePowNonce
import java.util.concurrent.TimeUnit

class PinApiClient(
    private val ffi: PinMobileClient,
    private val baseUrl: String = BuildConfig.API_BASE_URL.trimEnd('/'),
) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(25, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()
    private val binMedia = "application/octet-stream".toMediaType()

    @Volatile
    private var jwt: String? = null
    @Volatile
    private var jwtExpSec: Long = 0

    fun clearSession() {
        jwt = null
        jwtExpSec = 0
    }

    fun solvePow(action: Int, subjectBytes: ByteArray): Triple<String, String, String> {
        val chReq = Request.Builder()
            .url("$baseUrl/v1/pow/challenge")
            .post(JSONObject().put("action", action).toString().toRequestBody(jsonMedia))
            .build()
        val chJson = http.newCall(chReq).execute().use { res ->
            if (!res.isSuccessful) error("Error pidiendo PoW (${res.code})")
            JSONObject(res.body!!.string())
        }

        val payloadB64Url = chJson.getString("challengePayload")
        val idB64Url = chJson.getString("challengeId")
        val mac = chJson.getString("challengeMac")
        val diff = chJson.getInt("difficultyBits").toUByte()

        val payloadRaw = Base64.decode(payloadB64Url, Base64.URL_SAFE or Base64.NO_WRAP)
        val idRaw = Base64.decode(idB64Url, Base64.URL_SAFE or Base64.NO_WRAP)
        val nonceRaw = mobileSolvePowNonce(payloadRaw, idRaw, subjectBytes, diff)
        val nonceB64Url = Base64.encodeToString(nonceRaw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        return Triple(payloadB64Url, mac, nonceB64Url)
    }

    fun postJsonPublic(path: String, body: JSONObject): JSONObject {
        val req = Request.Builder()
            .url("$baseUrl$path")
            .post(body.toString().toRequestBody(jsonMedia))
            .build()
        return http.newCall(req).execute().use { res ->
            val txt = res.body?.string().orEmpty()
            if (!res.isSuccessful) error("HTTP ${res.code} en $path: $txt")
            JSONObject(txt)
        }
    }

    fun postRootBinary(path: String, headers: JSONObject, rawBody: ByteArray) {
        val req = Request.Builder()
            .url("$baseUrl$path")
            .header("X-Pin", headers.getString("xPin"))
            .header("X-Timestamp", headers.getString("xTimestamp"))
            .header("X-Nonce", headers.getString("xNonce"))
            .header("X-Signature", headers.getString("xSignature"))
            .post(rawBody.toRequestBody(binMedia))
            .build()
        http.newCall(req).execute().use { res ->
            if (!res.isSuccessful) error("HTTP ${res.code} en $path: ${res.body?.string().orEmpty()}")
        }
    }

    fun signedDevicePost(path: String, body: JSONObject): JSONObject {
        val raw = body.toString().toByteArray(Charsets.UTF_8)
        val nowSec = (System.currentTimeMillis() / 1000L).toULong()
        val sig = JSONObject(ffi.signDeviceHttpJson("POST", path, raw, nowSec))

        val req = Request.Builder()
            .url("$baseUrl$path")
            .header("X-Device-Id", sig.getString("xDeviceId"))
            .header("X-Timestamp", sig.getString("xTimestamp"))
            .header("X-Nonce", sig.getString("xNonce"))
            .header("X-Signature", sig.getString("xSignature"))
            .post(raw.toRequestBody(jsonMedia))
            .build()

        return http.newCall(req).execute().use { res ->
            val txt = res.body?.string().orEmpty()
            if (!res.isSuccessful) error("HTTP ${res.code} en $path: $txt")
            if (txt.isBlank()) JSONObject() else JSONObject(txt)
        }
    }

    fun getJwt(forceRefresh: Boolean = false): String {
        val now = System.currentTimeMillis() / 1000L
        val cached = jwt
        if (!forceRefresh && cached != null && jwtExpSec - now > 45) return cached
        val resp = signedDevicePost("/v1/auth/token", JSONObject())
        jwt = resp.getString("accessToken")
        jwtExpSec = resp.getLong("expiresAtSec")
        return jwt!!
    }

    fun authedJson(path: String, method: String = "GET", body: JSONObject? = null): JSONObject {
        val token = getJwt()
        val builder = Request.Builder()
            .url("$baseUrl$path")
            .header("Authorization", "Bearer $token")
        if (method == "POST") {
            builder.post((body ?: JSONObject()).toString().toRequestBody(jsonMedia))
        } else {
            builder.get()
        }
        return http.newCall(builder.build()).execute().use { res ->
            val txt = res.body?.string().orEmpty()
            if (!res.isSuccessful) error("HTTP ${res.code} en $path: $txt")
            if (txt.isBlank()) JSONObject() else JSONObject(txt)
        }
    }

    fun connectWebSocket(
        onSyncNeeded: () -> Unit,
        onRevoked4001: () -> Unit,
        onStatusChanged: (Boolean) -> Unit,
    ): WebSocket {
        val ticket = authedJson("/v1/auth/ws-ticket", "POST").getString("ticket")
        val wsUrl = baseUrl.replaceFirst("^http".toRegex(), "ws") + "/v1/ws?ticket=$ticket"
        val req = Request.Builder().url(wsUrl).build()

        return http.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                onStatusChanged(true)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                onSyncNeeded()
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                onStatusChanged(false)
                if (code == 4001) onRevoked4001()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                onStatusChanged(false)
            }
        })
    }
}
