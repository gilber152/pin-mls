package com.pinmls.app.ui

import android.app.Application
import android.util.Base64
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.pinmls.app.net.PinApiClient
import com.pinmls.app.security.VaultKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.WebSocket
import org.json.JSONArray
import org.json.JSONObject
import uniffi.pin_mobile_ffi.PinMobileClient
import uniffi.pin_mobile_ffi.mobileDeriveIdentityRegistrationJson
import uniffi.pin_mobile_ffi.mobileGenerateMnemonic12Words
import uniffi.pin_mobile_ffi.mobilePrepareDeviceEnrollmentJson
import java.io.File
import java.util.UUID

data class UiGroup(
    val groupIdB64: String,
    val groupIdB64Url: String,
    val peerPin: String,
    val epoch: Long,
    val active: Boolean,
)

data class UiMessage(
    val groupSeq: Long,
    val senderPin: String,
    val text: String,
    val mine: Boolean,
)

data class PinUiState(
    val initialized: Boolean = false,
    val pin: String = "",
    val deviceId: String = "",
    val wsOnline: Boolean = false,
    val busy: Boolean = false,
    val status: String = "Listo",
    val newMnemonicBanner: String? = null,
    val groups: List<UiGroup> = emptyList(),
    val activeGroupIdB64: String? = null,
    val activeMessages: List<UiMessage> = emptyList(),
)

class PinViewModel(app: Application) : AndroidViewModel(app) {
    private val dbFile = File(app.filesDir, "pin_mls_vault.db")
    private val dbKeyHex = VaultKeyManager.getOrCreateDbKeyHex(app)
    private val ffi = PinMobileClient.open(dbFile.absolutePath, dbKeyHex)
    private val api = PinApiClient(ffi)
    private var ws: WebSocket? = null

    private val _state = MutableStateFlow(PinUiState())
    val state: StateFlow<PinUiState> = _state.asStateFlow()

    init {
        refreshFromVault()
    }

    private fun refreshFromVault() {
        val summary = JSONObject(ffi.getAccountSummaryJson())
        val initialized = summary.getBoolean("initialized")
        if (!initialized) {
            _state.value = PinUiState(initialized = false, status = "Crea un PIN o vincula este equipo")
            return
        }

        val groupsArr = JSONArray(ffi.listGroupsJson())
        val groups = (0 until groupsArr.length()).map { i ->
            val g = groupsArr.getJSONObject(i)
            UiGroup(
                groupIdB64 = g.getString("groupIdB64"),
                groupIdB64Url = g.getString("groupIdB64Url"),
                peerPin = g.getString("peerPin"),
                epoch = g.getLong("epoch"),
                active = g.getBoolean("active"),
            )
        }
        val activeGid = _state.value.activeGroupIdB64 ?: groups.firstOrNull()?.groupIdB64
        val msgs = if (activeGid != null) loadMessages(activeGid) else emptyList()

        _state.value = _state.value.copy(
            initialized = true,
            pin = summary.getString("pin"),
            deviceId = summary.getString("deviceId"),
            groups = groups,
            activeGroupIdB64 = activeGid,
            activeMessages = msgs,
        )
    }

    private fun loadMessages(groupIdB64: String): List<UiMessage> {
        val arr = JSONArray(ffi.listMessagesJson(groupIdB64))
        return (0 until arr.length()).map { i ->
            val m = arr.getJSONObject(i)
            UiMessage(
                groupSeq = m.getLong("groupSeq"),
                senderPin = m.getString("senderPin"),
                text = m.getString("text"),
                mine = m.getBoolean("mine"),
            )
        }
    }

    fun selectGroup(groupIdB64: String) {
        _state.value = _state.value.copy(
            activeGroupIdB64 = groupIdB64,
            activeMessages = loadMessages(groupIdB64),
        )
    }

    fun dismissMnemonicBanner() {
        _state.value = _state.value.copy(newMnemonicBanner = null)
    }

    fun createNewPin() {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(busy = true, status = "Generando 12 palabras BIP-39...")
            try {
                val mnemonic = mobileGenerateMnemonic12Words()
                val reg = JSONObject(mobileDeriveIdentityRegistrationJson(mnemonic))

                _state.value = _state.value.copy(status = "Resolviendo PoW Argon2id (action=1)...")
                val pkRootBytes = reg.getString("pkRootHex").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val (powPayload, powMac, powNonce) = api.solvePow(1, pkRootBytes)

                val regResp = api.postJsonPublic(
                    "/v1/identities",
                    JSONObject()
                        .put("pkRoot", reg.getString("pkRootB64Url"))
                        .put("pkInvite", reg.getString("pkInviteB64Url"))
                        .put("sigInvite", reg.getString("sigInviteB64Url"))
                        .put("proofOfPossession", reg.getString("proofOfPossessionB64Url"))
                        .put("powPayload", powPayload)
                        .put("powMac", powMac)
                        .put("powNonce", powNonce),
                )
                val pin = regResp.getString("pin")

                _state.value = _state.value.copy(status = "Enrolando dispositivo Android para PIN $pin...")
                val nowSec = (System.currentTimeMillis() / 1000L).toULong()
                val enr = JSONObject(mobilePrepareDeviceEnrollmentJson(mnemonic, pin, nowSec))
                val certBytes = Base64.decode(enr.getString("deviceCertB64"), Base64.DEFAULT)
                api.postRootBinary("/v1/devices/enroll", enr.getJSONObject("enrollHeaders"), certBytes)

                ffi.initLocalAccount(
                    pin,
                    enr.getString("deviceId"),
                    reg.getString("pkRootHex"),
                    reg.getString("skInviteHex"),
                    reg.getString("pkInviteHex"),
                    enr.getString("skDevHex"),
                    enr.getString("pkDevHex"),
                )

                _state.value = _state.value.copy(status = "Subiendo 20 KeyPackages OpenMLS RFC 9420...")
                val kps = JSONArray(ffi.generateKeyPackagesJson(20u, true, nowSec))
                api.signedDevicePost("/v1/keypackages", JSONObject().put("keyPackages", kps))

                refreshFromVault()
                _state.value = _state.value.copy(
                    busy = false,
                    status = "Cuenta OpenMLS creada: PIN $pin",
                    newMnemonicBanner = mnemonic,
                )
                connectWs()
            } catch (e: Exception) {
                _state.value = _state.value.copy(busy = false, status = "Error: ${e.message}")
            }
        }
    }

    fun connectWs() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                ws?.close(1000, "reconnect")
                ws = api.connectWebSocket(
                    onSyncNeeded = { syncNow() },
                    onRevoked4001 = { wipeLocalVault("Dispositivo revocado por clave raíz (WS 4001)") },
                    onStatusChanged = { online -> _state.value = _state.value.copy(wsOnline = online) },
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(status = "WS error: ${e.message}")
            }
        }
    }

    fun syncNow() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val sync = api.authedJson("/v1/sync")
                val welcomes = sync.getJSONArray("welcomes")
                val ackWelcomeIds = JSONArray()
                for (i in 0 until welcomes.length()) {
                    val w = welcomes.getJSONObject(i)
                    ffi.joinFromWelcomeJson(w.getString("welcomeRaw"), w.getLong("commitSeq").toULong())
                    ackWelcomeIds.put(w.getString("welcomeBlobId"))
                }

                val envelopes = sync.getJSONArray("envelopes")
                val cursors = mutableMapOf<String, Long>()
                for (i in 0 until envelopes.length()) {
                    val env = envelopes.getJSONObject(i)
                    val gid = env.getString("groupId")
                    val seq = env.getLong("groupSeq")
                    runCatching {
                        ffi.processEnvelopeJson(gid, seq.toULong(), env.getString("ciphertext"))
                    }
                    cursors[gid] = maxOf(cursors[gid] ?: 0L, seq)
                }

                if (ackWelcomeIds.length() > 0 || cursors.isNotEmpty()) {
                    val curArr = JSONArray()
                    cursors.forEach { (gid, lastSeq) ->
                        curArr.put(JSONObject().put("groupId", gid).put("lastSeq", lastSeq))
                    }
                    api.authedJson(
                        "/v1/acks",
                        "POST",
                        JSONObject().put("welcomeBlobIds", ackWelcomeIds).put("groupCursors", curArr),
                    )
                }
                refreshFromVault()
            } catch (e: Exception) {
                _state.value = _state.value.copy(status = "Sync: ${e.message}")
            }
        }
    }

    fun sendMessage(text: String) {
        val clean = text.trim()
        val gid = _state.value.activeGroupIdB64 ?: return
        val grp = _state.value.groups.firstOrNull { it.groupIdB64 == gid } ?: return
        if (clean.isEmpty()) return

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val nowMs = System.currentTimeMillis()
                val enc = JSONObject(ffi.encryptMessageJson(gid, clean, nowMs))
                val resp = api.authedJson(
                    "/v1/groups/${grp.groupIdB64Url}/messages",
                    "POST",
                    JSONObject()
                        .put("msgType", "application")
                        .put("epoch", enc.getLong("epoch"))
                        .put("clientMsgId", UUID.randomUUID().toString())
                        .put("ciphertext", enc.getString("ciphertextB64")),
                )
                ffi.recordSentMessage(gid, resp.getLong("groupSeq").toULong(), clean, nowMs)
                refreshFromVault()
            } catch (e: Exception) {
                _state.value = _state.value.copy(status = "Error enviando: ${e.message}")
            }
        }
    }

    fun wipeLocalVault(reason: String = "Bóveda local borrada") {
        viewModelScope.launch(Dispatchers.IO) {
            ws?.close(1000, "wipe")
            ws = null
            api.clearSession()
            ffi.wipeVault()
            _state.value = PinUiState(initialized = false, status = reason)
        }
    }
}
