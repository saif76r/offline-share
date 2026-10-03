package com.offlineshare.app.ui

import android.app.Application
import android.content.Context
import android.net.Uri
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pDevice
import android.os.Build
import android.os.PowerManager
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.offlineshare.app.pairing.PairingClient
import com.offlineshare.app.pairing.PairingException
import com.offlineshare.app.pairing.QrPayload
import com.offlineshare.app.security.Session
import com.offlineshare.app.storage.HistoryItem
import com.offlineshare.app.storage.HistoryStore
import com.offlineshare.app.storage.Names
import com.offlineshare.app.storage.Storage
import com.offlineshare.app.transfer.RemoteFile
import com.offlineshare.app.transfer.ReceiveServer
import com.offlineshare.app.transfer.SpeedMeter
import com.offlineshare.app.transfer.TransferClient
import com.offlineshare.app.transfer.TransferException
import com.offlineshare.app.wifi.WifiDirectManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.UUID
import java.util.concurrent.TimeUnit

data class PeerUi(val device: WifiP2pDevice, val name: String, val status: String, val isComputer: Boolean)
data class PickedFile(val uri: Uri, val name: String, val size: Long, val checked: Boolean = true)
data class TransferUi(val key: String, val name: String, val size: Long, val done: Long = 0, val state: String = "Waiting",
                      val speed: Long = 0, val eta: Long = -1, val upload: Boolean = true, val finished: Boolean = false)

data class IncomingUi(val id: String, val name: String, val size: Long, val offset: Long, val state: String, val device: String, val error: String)
data class ReceiveUi(val active: Boolean = false, val pin: String = "", val pinTtl: Int = 0, val paired: List<String> = emptyList(), val incoming: List<IncomingUi> = emptyList())

data class UiState(
    val receive: ReceiveUi = ReceiveUi(),
    val wifiSupported: Boolean = true, val status: String = "", val peers: List<PeerUi> = emptyList(),
    val connected: Boolean = false, val serverName: String? = null, val askPin: Boolean = false, val busy: String? = null,
    val message: String? = null, val canReconnect: Boolean = false, val canResume: Boolean = false, val canJoinWifi: Boolean = false,
    val staged: List<PickedFile> = emptyList(), val transfers: List<TransferUi> = emptyList(),
    val remote: List<RemoteFile> = emptyList(), val remoteChecked: Set<String> = emptySet(), val history: List<HistoryItem> = emptyList())

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val ctx: Context = app.applicationContext
    val wifi = WifiDirectManager(ctx)
    private val notifier = Notifier(ctx)
    private val historyStore = HistoryStore(ctx)
    private val prefs = ctx.getSharedPreferences("offlineshare", Context.MODE_PRIVATE)
    private val deviceId = prefs.getString("device_id", null) ?: UUID.randomUUID().toString().also { prefs.edit().putString("device_id", it).apply() }

    private val _ui = MutableStateFlow(UiState(wifiSupported = wifi.supported))
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private var session: Session? = null
    private var client: TransferClient? = null
    private var qr: QrPayload? = null
    private var resumeAction: (() -> Unit)? = null
    private var job: Job? = null
    private var server: ReceiveServer? = null
    private var ticker: Job? = null
    private val uploadIds = mutableMapOf<String, String>()
    private val hashes = mutableMapOf<String, String>()

    init {
        wifi.start()
        viewModelScope.launch {
            combine(wifi.status, wifi.peers, wifi.ownerIp, wifi.specifierNetwork) { s, p, _, _ -> s to p }.collect { (s, p) ->
                _ui.update { it.copy(status = s, peers = p.map(::peerUi).sortedByDescending { x -> x.isComputer }) }
            }
        }
        // Stay visible to the laptop / other phones (like a wireless mouse showing up in a Bluetooth list).
        viewModelScope.launch { while (true) { if (wifi.supported) wifi.discover(); delay(30_000) } }
        // The laptop (or another phone) connected to us at link level -> ask for the PIN straight away.
        viewModelScope.launch {
            wifi.ownerIp.collect { ip ->
                val s = _ui.value
                if (ip != null && !s.connected && qr == null && s.busy == null && !s.receive.active) _ui.update { it.copy(askPin = true) }
            }
        }
        refreshHistory()
    }

    // ---------------------------------------------------------------- receive from another phone
    fun startReceiving() {
        if (server != null) return
        val srv = ReceiveServer(8080, Storage.partDir(ctx), Build.MODEL,
            publish = { f, n -> Storage.publishReceived(ctx, f, n) },
            onDone = { h -> historyStore.add(h); refreshHistory(); if (h.status == "Completed") notifier.done(h.name.hashCode(), h.name) },
            onChange = { pushReceive() })
        try { srv.start(15_000, true) } catch (e: IOException) { return fail("Could not start receiving: ${e.message}") }
        server = srv
        wifi.createGroup { err -> if (err != null) fail(err) }
        pushReceive()
        ticker = viewModelScope.launch { while (true) { pushReceive(); delay(1000) } }
    }

    fun stopReceiving() {
        ticker?.cancel(); server?.stop(); server = null; wifi.disconnect()
        _ui.update { it.copy(receive = ReceiveUi()) }
    }

    fun decideIncoming(id: String, accept: Boolean) { server?.decide(id, accept) }

    private fun pushReceive() {
        val srv = server ?: return
        val (pin, ttl) = srv.currentPin()
        val list = srv.incoming.values.filter { it.state in setOf("pending", "accepted", "receiving", "failed") }
            .map { IncomingUi(it.id, it.name, it.size, it.offset, it.state, it.device, it.error) }
        _ui.update { it.copy(receive = ReceiveUi(true, pin, ttl, srv.pairedDevices(), list)) }
    }

    private fun peerUi(d: WifiP2pDevice) = PeerUi(d, d.deviceName.ifBlank { d.deviceAddress }, when (d.status) {
        WifiP2pDevice.CONNECTED -> "Connected"; WifiP2pDevice.AVAILABLE -> "Available"; WifiP2pDevice.INVITED -> "Invited"
        WifiP2pDevice.FAILED -> "Failed"; else -> "Out of range" }, d.primaryDeviceType?.startsWith("1-") == true)

    private fun fail(msg: String?, resume: Boolean = false, reconnect: Boolean = false, joinWifi: Boolean = false) =
        _ui.update { it.copy(busy = null, message = msg, canResume = resume, canReconnect = reconnect, canJoinWifi = joinWifi) }

    fun dismissMessage() = _ui.update { it.copy(message = null, canResume = false, canReconnect = false, canJoinWifi = false) }
    fun discover() = wifi.discover()

    // ---------------------------------------------------------------- connecting
    fun connectPeer(p: PeerUi) {
        qr = null
        _ui.update { it.copy(busy = "Connecting to ${p.name}…", message = null) }
        wifi.connect(p.device) { err ->
            if (err != null) fail(err) else viewModelScope.launch {
                val ip = withTimeoutOrNull(25_000) { wifi.ownerIp.filterNotNull().first() }
                if (ip == null) fail("Laptop did not accept the Wi-Fi Direct connection. Try the QR code instead.")
                else _ui.update { it.copy(busy = null, askPin = true) }
            }
        }
    }

    fun handleQr(text: String) {
        val q = QrPayload.parse(text) ?: return fail("That is not an OfflineShare QR code.")
        qr = q
        _ui.update { it.copy(busy = "Joining ${q.name} over Wi-Fi Direct…", message = null) }
        wifi.connectWithCredentials(q.ssid, q.passphrase) { err ->
            if (err != null) fail(err, joinWifi = true) else viewModelScope.launch {
                val up = withTimeoutOrNull(30_000) { wifi.ownerIp.filterNotNull().first() }
                if (up == null) fail("Could not join the laptop's Wi-Fi Direct group.", joinWifi = true) else pairWith(q.secret)
            }
        }
    }

    /** Explicit user action after P2P join failed: connect to the laptop's own Wi-Fi Direct SSID as a plain Wi-Fi link. */
    fun joinViaWifi() {
        val q = qr ?: return
        _ui.update { it.copy(busy = "Joining ${q.ssid}…", message = null) }
        wifi.joinViaWifiSpecifier(q.ssid, q.passphrase) { err -> if (err != null) fail(err, joinWifi = true) else pairWith(q.secret) }
    }

    fun submitPin(pin: String) = pairWith(pin.trim())
    fun cancelPin() = _ui.update { it.copy(askPin = false) }

    private fun httpClient(): OkHttpClient {
        val b = OkHttpClient.Builder().connectTimeout(8, TimeUnit.SECONDS).readTimeout(15, TimeUnit.MINUTES).writeTimeout(2, TimeUnit.MINUTES)
        wifi.directNetwork()?.let { b.socketFactory(it.socketFactory) }
        return b.build()
    }

    private fun addressCandidates() = (qr?.ips ?: emptyList()) + listOfNotNull(wifi.ownerIp.value)

    private fun pairWith(secret: String) {
        viewModelScope.launch {
            _ui.update { it.copy(busy = "Pairing…", askPin = false, message = null) }
            try {
                val http = httpClient()
                val base = PairingClient.findServer(http, addressCandidates(), qr?.port ?: 8080)
                    ?: throw IOException("Laptop not reachable on the direct link. Is OfflineShare running on the laptop?")
                val s = PairingClient.pair(http, base, secret, deviceId, Build.MODEL)
                session = s; client = TransferClient(http, s)
                _ui.update { it.copy(connected = true, serverName = qr?.name ?: "Laptop", busy = null, message = null) }
                refreshRemote()
            } catch (e: PairingException) { fail(e.message, reconnect = false) }
            catch (e: Exception) { fail("Connection failed: ${e.message}", reconnect = true) }
        }
    }

    fun reconnect() = viewModelScope.launch {
        val base = PairingClient.findServer(httpClient(), addressCandidates(), qr?.port ?: 8080)
        if (base == null) fail("Still can't reach the laptop. Re-scan its QR code.", reconnect = true)
        else {
            // The IP may have changed (Wi-Fi turned off/on): keep the keys, just point the session at the new address.
            session = session?.withBase(base); client = session?.let { TransferClient(httpClient(), it) }; dismissMessage()
        }
    }

    fun disconnect() {
        job?.cancel(); wifi.disconnect(); session = null; client = null; qr = null
        _ui.update { it.copy(connected = false, serverName = null, transfers = emptyList(), remote = emptyList(), message = null) }
    }

    // ---------------------------------------------------------------- phone -> laptop
    fun stage(uris: List<Uri>) {
        val picked = uris.map { u ->
            ctx.contentResolver.query(u, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst()) PickedFile(u, Names.sanitize(c.getString(0) ?: "file"), c.getLong(1)) else null } ?: PickedFile(u, "file", 0)
        }
        _ui.update { it.copy(staged = it.staged + picked) }
    }

    fun toggleStaged(u: Uri) = _ui.update { s -> s.copy(staged = s.staged.map { if (it.uri == u) it.copy(checked = !it.checked) else it }) }

    fun sendStaged() {
        val items = _ui.value.staged.filter { it.checked }
        if (items.isEmpty() || client == null) return
        _ui.update { s -> s.copy(staged = s.staged.filterNot { it.checked }, transfers = s.transfers.filterNot { it.upload } +
            items.map { TransferUi(it.uri.toString(), it.name, it.size) }) }
        runUploads(items)
    }

    private fun runUploads(items: List<PickedFile>) {
        job?.cancel()
        job = viewModelScope.launch {
            val c = client ?: return@launch fail("Not connected")
            holdingLocks {
                for (f in items) {
                    val key = f.uri.toString(); val nid = key.hashCode()
                    if (_ui.value.transfers.firstOrNull { it.key == key }?.finished == true) continue
                    val t0 = System.currentTimeMillis()
                    try {
                        setT(key) { it.copy(state = "Checking file…") }
                        val sha = hashes.getOrPut(key) { c.hashUri(ctx, f.uri) }
                        val id = uploadIds.getOrPut(key) { c.initUpload(f.name, f.size, sha) }
                        setT(key) { it.copy(state = "Waiting for laptop to accept…") }
                        c.awaitAccepted(id)
                        val meter = SpeedMeter(f.size)
                        c.upload(ctx, f.uri, id, f.size) { done ->
                            val (bps, eta) = meter.update(done)
                            setT(key) { it.copy(done = done, speed = bps, eta = eta, state = "Sending") }
                            notifier.progress(nid, f.name, if (f.size > 0) (done * 100 / f.size).toInt() else 100, true)
                        }
                        setT(key) { it.copy(done = f.size, state = "Integrity verified ✓", finished = true, speed = 0) }
                        notifier.done(nid, f.name); uploadIds.remove(key)
                        historyStore.add(HistoryItem(f.name, f.size, "Phone → Laptop", _ui.value.serverName ?: "Laptop", "Completed", sha, System.currentTimeMillis(), System.currentTimeMillis() - t0))
                        refreshHistory()
                    } catch (e: CancellationException) { throw e }
                    catch (e: Exception) {
                        val resumable = (e as? TransferException)?.resumable ?: (e is IOException)
                        setT(key) { it.copy(state = "Interrupted") }
                        notifier.failed(nid, f.name, e.message ?: "error")
                        if (e is TransferException && e.message?.contains("SHA-256") == true) uploadIds.remove(key)
                        resumeAction = { runUploads(items) }
                        fail((e.message ?: "Transfer failed") + if (resumable) "\n\nYour file is safe. You can resume the transfer." else "", resume = resumable, reconnect = true)
                        return@holdingLocks
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- laptop -> phone
    fun refreshRemote() {
        val c = client ?: return
        viewModelScope.launch {
            try { val files = c.listFiles(); _ui.update { it.copy(remote = files, remoteChecked = files.map { f -> f.id }.toSet()) } }
            catch (e: Exception) { fail("Could not list laptop files: ${e.message}", reconnect = true) }
        }
    }

    fun toggleRemote(id: String) = _ui.update { it.copy(remoteChecked = if (id in it.remoteChecked) it.remoteChecked - id else it.remoteChecked + id) }
    fun rejectRemote() = _ui.update { it.copy(remoteChecked = emptySet()) }

    fun acceptRemote() {
        val files = _ui.value.remote.filter { it.id in _ui.value.remoteChecked }
        if (files.isEmpty()) return
        _ui.update { s -> s.copy(transfers = s.transfers.filter { it.upload } + files.map { TransferUi("dl:${it.id}", it.name, it.size, upload = false) }) }
        runDownloads(files)
    }

    private fun runDownloads(files: List<RemoteFile>) {
        job?.cancel()
        job = viewModelScope.launch {
            val c = client ?: return@launch fail("Not connected")
            holdingLocks {
                for (f in files) {
                    val key = "dl:${f.id}"; val nid = key.hashCode()
                    if (_ui.value.transfers.firstOrNull { it.key == key }?.finished == true) continue
                    val t0 = System.currentTimeMillis(); val meter = SpeedMeter(f.size)
                    try {
                        val part = Storage.partFile(ctx, f.id)
                        setT(key) { it.copy(state = "Receiving") }
                        c.download(f, part) { done ->
                            val (bps, eta) = meter.update(done)
                            setT(key) { it.copy(done = done, speed = bps, eta = eta) }
                            notifier.progress(nid, f.name, if (f.size > 0) (done * 100 / f.size).toInt() else 100, false)
                        }
                        val saved = Storage.publishReceived(ctx, part, f.name)
                        setT(key) { it.copy(done = f.size, state = "Integrity verified ✓ · saved to Downloads/OfflineShare/Received", finished = true, speed = 0) }
                        notifier.done(nid, saved)
                        historyStore.add(HistoryItem(saved, f.size, "Laptop → Phone", _ui.value.serverName ?: "Laptop", "Completed", f.sha256, System.currentTimeMillis(), System.currentTimeMillis() - t0))
                        refreshHistory()
                    } catch (e: CancellationException) { throw e }
                    catch (e: Exception) {
                        val resumable = (e as? TransferException)?.resumable ?: (e is IOException)
                        setT(key) { it.copy(state = "Interrupted") }
                        notifier.failed(nid, f.name, e.message ?: "error")
                        resumeAction = { runDownloads(files) }
                        fail((e.message ?: "Transfer failed") + if (resumable) "\n\nYour file is safe. You can resume the transfer." else "", resume = resumable, reconnect = true)
                        return@holdingLocks
                    }
                }
            }
        }
    }

    fun resume() { dismissMessage(); resumeAction?.invoke() }

    // ---------------------------------------------------------------- helpers
    private fun setT(key: String, f: (TransferUi) -> TransferUi) =
        _ui.update { s -> s.copy(transfers = s.transfers.map { if (it.key == key) f(it) else it }) }

    private fun refreshHistory() = _ui.update { it.copy(history = historyStore.all()) }

    /** Keeps the CPU and Wi-Fi radio awake while transferring (screen off / doze). */
    private suspend fun holdingLocks(block: suspend () -> Unit) {
        val wl = (ctx.getSystemService(Context.POWER_SERVICE) as PowerManager).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OfflineShare:transfer")
        @Suppress("DEPRECATION")
        val fl = (ctx.getSystemService(Context.WIFI_SERVICE) as WifiManager).createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "OfflineShare")
        wl.acquire(2 * 60 * 60 * 1000L); fl.acquire()
        try { block() } finally { if (wl.isHeld) wl.release(); if (fl.isHeld) fl.release() }
    }

    override fun onCleared() { server?.stop(); wifi.stop(); super.onCleared() }
}
