package com.offlineshare.app.wifi

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WpsInfo
import android.net.wifi.WifiNetworkSpecifier
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

const val WIFI_DIRECT_UNAVAILABLE = "Wi-Fi Direct is unavailable on this device.\n\nNo internet or Bluetooth fallback will be used."

/** Wraps WifiP2pManager: discovery, connecting, and finding the P2P [Network] so sockets use the direct link. */
@SuppressLint("MissingPermission")
class WifiDirectManager(private val ctx: Context) {
    private val manager = ctx.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    private val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var channel: WifiP2pManager.Channel? = null
    private var receiver: BroadcastReceiver? = null
    private var specCallback: ConnectivityManager.NetworkCallback? = null

    val supported = ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT) && manager != null

    private val _enabled = MutableStateFlow(false)
    private val _peers = MutableStateFlow<List<WifiP2pDevice>>(emptyList())
    private val _status = MutableStateFlow(if (supported) "Starting…" else WIFI_DIRECT_UNAVAILABLE)
    private val _ownerIp = MutableStateFlow<String?>(null)
    private val _specNet = MutableStateFlow<Network?>(null)
    val enabled: StateFlow<Boolean> = _enabled.asStateFlow()
    val peers: StateFlow<List<WifiP2pDevice>> = _peers.asStateFlow()
    val status: StateFlow<String> = _status.asStateFlow()
    /** Group-owner (laptop) IP once a P2P group is formed. */
    val ownerIp: StateFlow<String?> = _ownerIp.asStateFlow()
    /** Set when the user explicitly chose "Join via Wi-Fi" (direct link to the laptop's own network, no internet). */
    val specifierNetwork: StateFlow<Network?> = _specNet.asStateFlow()

    fun start() {
        val m = manager ?: return
        if (!supported || receiver != null) return
        channel = m.initialize(ctx, ctx.mainLooper, null)
        val f = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION); addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        }
        receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                when (i.action) {
                    WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                        val on = i.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1) == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                        _enabled.value = on
                        _status.value = if (on) "Ready" else "Wi-Fi Direct is turned off. Turn Wi-Fi on."
                    }
                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> m.requestPeers(channel) { _peers.value = it.deviceList.toList() }
                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> m.requestConnectionInfo(channel) { info ->
                        _ownerIp.value = if (info.groupFormed && !info.isGroupOwner) info.groupOwnerAddress?.hostAddress else null
                    }
                }
            }
        }
        ctx.registerReceiver(receiver, f)
    }

    fun stop() {
        receiver?.let { runCatching { ctx.unregisterReceiver(it) } }; receiver = null
        manager?.stopPeerDiscovery(channel, null)
    }

    /** Also what makes THIS phone visible to the laptop / another phone (Wi-Fi Direct devices are visible while discovering). */
    fun discover() {
        try {
            manager?.discoverPeers(channel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() { _status.value = "Ready · visible to nearby devices" }
                override fun onFailure(reason: Int) { _status.value = "Discovery failed (${reasonText(reason)})" }
            })
        } catch (e: SecurityException) { _status.value = "Allow 'Nearby devices' permission to find devices" }
    }

    /** Receive mode: become the group owner so the sender joins us and learns our IP. */
    fun createGroup(onResult: (String?) -> Unit) {
        manager?.removeGroup(channel, null)
        manager?.createGroup(channel, listener(onResult))
    }

    /** Tap-a-device flow. The laptop is asked to be group owner (we use the lowest intent). */
    fun connect(device: WifiP2pDevice, onResult: (String?) -> Unit) {
        val cfg = WifiP2pConfig().apply { deviceAddress = device.deviceAddress; wps.setup = WpsInfo.PBC; groupOwnerIntent = 0 }
        manager?.connect(channel, cfg, listener(onResult))
    }

    /** QR flow: join the laptop's Wi-Fi Direct group using the SSID/passphrase from the QR code. */
    fun connectWithCredentials(ssid: String, passphrase: String, onResult: (String?) -> Unit) {
        val cfg = WifiP2pConfig.Builder().setNetworkName(ssid).setPassphrase(passphrase).build()
        manager?.connect(channel, cfg, listener(onResult))
    }

    /** Explicit, user-triggered alternative if P2P join fails: connect to the laptop's Wi-Fi Direct SSID as a normal Wi-Fi link. */
    fun joinViaWifiSpecifier(ssid: String, passphrase: String, onResult: (String?) -> Unit) {
        val spec = WifiNetworkSpecifier.Builder().setSsid(ssid).setWpa2Passphrase(passphrase).build()
        val req = NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).setNetworkSpecifier(spec).build()
        specCallback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        specCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { _specNet.value = network; onResult(null) }
            override fun onUnavailable() { onResult("Could not join the laptop's Wi-Fi Direct network.") }
            override fun onLost(network: Network) { _specNet.value = null }
        }
        cm.requestNetwork(req, specCallback!!, 30_000)
    }

    /** The Network object for the direct link, so sockets don't get routed over mobile data. */
    fun directNetwork(): Network? = _specNet.value ?: cm.allNetworks.firstOrNull {
        cm.getLinkProperties(it)?.interfaceName?.startsWith("p2p") == true
    }

    fun disconnect() {
        manager?.removeGroup(channel, null)
        specCallback?.let { runCatching { cm.unregisterNetworkCallback(it) } }; specCallback = null
        _specNet.value = null; _ownerIp.value = null
    }

    private fun listener(cb: (String?) -> Unit) = object : WifiP2pManager.ActionListener {
        override fun onSuccess() = cb(null)
        override fun onFailure(reason: Int) = cb("Could not connect (${reasonText(reason)})")
    }

    private fun reasonText(r: Int) = when (r) {
        WifiP2pManager.P2P_UNSUPPORTED -> "Wi-Fi Direct unsupported"; WifiP2pManager.BUSY -> "busy, try again"
        WifiP2pManager.ERROR -> "internal error"; else -> "code $r"
    }
}
