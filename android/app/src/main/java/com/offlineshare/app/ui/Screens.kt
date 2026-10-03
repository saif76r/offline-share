package com.offlineshare.app.ui

import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.background
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.offlineshare.app.storage.HistoryItem
import com.offlineshare.app.transfer.RemoteFile
import java.text.DateFormat
import java.util.Date

@Composable
fun OfflineShareTheme(content: @Composable () -> Unit) {
    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme(primary = Color(0xFF8AB4FF)) else -> lightColorScheme(primary = Color(0xFF3B6DF0))
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

fun fmtSize(n: Long): String = when {
    n < 1024 -> "$n B"; n < 1 shl 20 -> "%.1f KB".format(n / 1024.0)
    n < 1L shl 30 -> "%.1f MB".format(n / 1048576.0); else -> "%.2f GB".format(n / 1073741824.0)
}
private fun fmtEta(s: Long) = if (s < 0) "–" else if (s < 60) "${s}s" else "${s / 60}m ${s % 60}s"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OfflineShareApp(vm: MainViewModel, onPickFiles: () -> Unit, onScanQr: () -> Unit) {
    val s by vm.ui.collectAsState()
    var tab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Home" to Icons.Default.Home, "Send" to Icons.Default.Upload, "Receive" to Icons.Default.Download, "History" to Icons.Default.History)

    Scaffold(
        topBar = { CenterAlignedTopAppBar(title = { Text("OfflineShare", fontWeight = FontWeight.Bold) }) },
        bottomBar = { NavigationBar { tabs.forEachIndexed { i, (n, ic) -> NavigationBarItem(tab == i, { tab = i }, { Icon(ic, n) }, label = { Text(n) }) } } },
    ) { pad ->
        Column(Modifier.padding(pad).padding(horizontal = 16.dp)) {
            s.busy?.let { LinearProgressIndicator(Modifier.fillMaxWidth()); Text(it, Modifier.padding(vertical = 6.dp), fontSize = 13.sp) }
            s.message?.let { MessageCard(s, vm) }
            when (tab) {
                0 -> Home(s, vm, onScanQr)
                1 -> SendTab(s, vm, onPickFiles)
                2 -> ReceiveTab(s, vm)
                else -> HistoryTab(s.history)
            }
        }
    }
    if (s.askPin) PinDialog(onPair = vm::submitPin, onCancel = vm::cancelPin)
}

@Composable
private fun StatusDot(on: Boolean) = Box(Modifier.size(12.dp).clip(CircleShape).background(if (on) Color(0xFF1FA971) else Color(0xFF9AA3B2)))

@Composable
private fun MessageCard(s: UiState, vm: MainViewModel) = Card(Modifier.fillMaxWidth().padding(vertical = 6.dp),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
    Column(Modifier.padding(14.dp)) {
        Text(s.message ?: "", color = MaterialTheme.colorScheme.onErrorContainer)
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s.canReconnect) OutlinedButton(vm::reconnect) { Text("Reconnect") }
            if (s.canResume) Button(vm::resume) { Text("Resume") }
            if (s.canJoinWifi) OutlinedButton(vm::joinViaWifi) { Text("Join via Wi-Fi (direct)") }
            TextButton(vm::dismissMessage) { Text("Dismiss") }
        }
    }
}

@Composable
private fun Home(s: UiState, vm: MainViewModel, onScanQr: () -> Unit) = LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
    item {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
            StatusDot(s.connected); Spacer(Modifier.width(8.dp))
            Text(if (s.connected) "Connected to ${s.serverName}" else if (s.wifiSupported) "Ready" else "Unavailable", fontWeight = FontWeight.SemiBold)
        }
        if (!s.wifiSupported || s.status.startsWith("Wi-Fi Direct")) Text(s.status, Modifier.padding(top = 6.dp), color = MaterialTheme.colorScheme.error)
        else if (s.status.isNotBlank()) Text(s.status, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    item {
        Button(onScanQr, Modifier.fillMaxWidth().height(56.dp), enabled = s.wifiSupported && !s.connected) {
            Icon(Icons.Default.QrCodeScanner, null); Spacer(Modifier.width(8.dp)); Text("Scan laptop QR code")
        }
    }
    item { ReceiveCard(s, vm) }
    if (s.connected) item { OutlinedButton(vm::disconnect, Modifier.fillMaxWidth()) { Text("Disconnect") } }
    else {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Nearby devices", Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                TextButton(vm::discover, enabled = s.wifiSupported) { Text("Search") }
            }
        }
        if (s.peers.isEmpty()) item { Text("No devices found yet. Tap Search, or scan the QR code shown on the laptop.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        items(s.peers, key = { it.device.deviceAddress }) { p ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(if (p.isComputer) "💻" else "📱", fontSize = 26.sp); Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) { Text(p.name, fontWeight = FontWeight.Medium); Text(p.status, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    Button({ vm.connectPeer(p) }) { Text("Connect") }
                }
            }
        }
    }
}

@Composable
private fun SendTab(s: UiState, vm: MainViewModel, onPick: () -> Unit) = LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
    item {
        Button(onPick, Modifier.fillMaxWidth().height(56.dp).padding(top = 4.dp), enabled = s.connected) { Icon(Icons.Default.AttachFile, null); Spacer(Modifier.width(8.dp)); Text("Select Files") }
        if (!s.connected) Text("Connect to the laptop first (Home tab).", Modifier.padding(top = 6.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    items(s.staged, key = { it.uri.toString() }) { f ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(f.checked, { vm.toggleStaged(f.uri) }); Column { Text(f.name); Text(fmtSize(f.size), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
    if (s.staged.isNotEmpty()) item {
        val sel = s.staged.filter { it.checked }
        Text("Total: ${sel.size} files · ${fmtSize(sel.sumOf { it.size })}", fontWeight = FontWeight.SemiBold)
        Button(vm::sendStaged, Modifier.fillMaxWidth().height(52.dp), enabled = sel.isNotEmpty()) { Text("Send") }
    }
    transferRows(s.transfers.filter { it.upload })
}

private fun androidx.compose.foundation.lazy.LazyListScope.transferRows(list: List<TransferUi>) {
    if (list.isEmpty()) return
    item {
        val total = list.sumOf { it.size }.coerceAtLeast(1); val done = list.sumOf { it.done }
        Text("Overall · ${list.count { it.finished }}/${list.size} files", fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 10.dp))
        LinearProgressIndicator(progress = { done.toFloat() / total }, Modifier.fillMaxWidth().padding(vertical = 4.dp))
    }
    items(list, key = { it.key }) { t ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                Text(t.name, fontWeight = FontWeight.Medium, maxLines = 1)
                Text("${fmtSize(t.done)} / ${fmtSize(t.size)} · ${t.state}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                LinearProgressIndicator(progress = { if (t.size == 0L) (if (t.finished) 1f else 0f) else t.done.toFloat() / t.size }, Modifier.fillMaxWidth().padding(vertical = 6.dp))
                if (!t.finished && t.speed > 0) Text("${fmtSize(t.speed)}/s · ${fmtEta(t.eta)} left", fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun ReceiveTab(s: UiState, vm: MainViewModel) = LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
    item {
        Row(Modifier.padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Files on the laptop", Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
            TextButton(vm::refreshRemote, enabled = s.connected) { Text("Refresh") }
        }
        if (!s.connected) Text("Connect to the laptop first (Home tab).", color = MaterialTheme.colorScheme.onSurfaceVariant)
        else if (s.remote.isEmpty()) Text("Nothing queued. On the laptop, select files in the dashboard, then Refresh.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    items(s.remote, key = { it.id }) { f: RemoteFile ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(f.id in s.remoteChecked, { vm.toggleRemote(f.id) })
            Column { Text("📄 ${f.name}"); Text(fmtSize(f.size), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
    if (s.remote.isNotEmpty()) item {
        val sel = s.remote.filter { it.id in s.remoteChecked }
        Text(if (sel.size == 1) "Incoming File · ${fmtSize(sel[0].size)}" else "Incoming Transfer · ${sel.size} files · ${fmtSize(sel.sumOf { it.size })}", fontWeight = FontWeight.SemiBold)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton(vm::rejectRemote, Modifier.weight(1f)) { Text("Reject") }
            Button(vm::acceptRemote, Modifier.weight(1f), enabled = sel.isNotEmpty()) { Text(if (sel.size > 1) "Accept All" else "Accept") }
        }
    }
    transferRows(s.transfers.filter { !it.upload })
}

@Composable
private fun HistoryTab(items: List<HistoryItem>) = LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
    if (items.isEmpty()) item { Text("No transfers yet.", Modifier.padding(top = 12.dp)) }
    items(items) { h ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                Text(h.name, fontWeight = FontWeight.Medium)
                Text("${h.direction} · ${fmtSize(h.size)} · ${h.status}", fontSize = 12.sp)
                Text("SHA-256 ${h.sha256.take(16)}… · ${"%.1f".format(h.durationMs / 1000.0)} s", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(DateFormat.getDateTimeInstance().format(Date(h.ts)), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun PinDialog(onPair: (String) -> Unit, onCancel: () -> Unit) {
    var pin by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onCancel, title = { Text("Enter PIN") },
        text = {
            Column {
                Text("Type the 6-digit PIN shown on the laptop.")
                OutlinedTextField(pin, { if (it.length <= 6 && it.all(Char::isDigit)) pin = it }, Modifier.padding(top = 12.dp).fillMaxWidth(), singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontSize = 28.sp, letterSpacing = 8.sp, textAlign = TextAlign.Center),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword))
            }
        },
        confirmButton = { Button({ onPair(pin) }, enabled = pin.length == 6) { Text("Pair Device") } },
        dismissButton = { TextButton(onCancel) { Text("Cancel") } })
}

@Composable
private fun ReceiveCard(s: UiState, vm: MainViewModel) = Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("📥 Receive from another phone", fontWeight = FontWeight.SemiBold)
                Text("Turn on, then on the other phone open Nearby devices and tap this phone.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(s.receive.active, { if (it) vm.startReceiving() else vm.stopReceiving() }, enabled = s.wifiSupported && !s.connected)
        }
        if (s.receive.active) {
            Text("Pairing PIN", Modifier.padding(top = 10.dp), fontSize = 12.sp)
            Text(s.receive.pin, fontSize = 34.sp, letterSpacing = 6.sp, fontWeight = FontWeight.Bold)
            Text("new PIN in ${s.receive.pinTtl}s · single use" + if (s.receive.paired.isNotEmpty()) " · paired: ${s.receive.paired.joinToString()}" else "", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            s.receive.incoming.forEach { t ->
                Column(Modifier.padding(top = 10.dp)) {
                    Text(if (t.state == "pending") "Incoming File from ${t.device}" else t.name, fontWeight = FontWeight.Medium)
                    Text("📄 ${t.name} · ${fmtSize(t.size)} · ${t.state}${if (t.error.isNotBlank()) " · " + t.error else ""}", fontSize = 12.sp)
                    if (t.state == "receiving" || t.state == "accepted") LinearProgressIndicator(progress = { if (t.size == 0L) 0f else t.offset.toFloat() / t.size }, Modifier.fillMaxWidth().padding(vertical = 4.dp))
                    if (t.state == "pending") Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton({ vm.decideIncoming(t.id, false) }) { Text("Reject") }
                        Button({ vm.decideIncoming(t.id, true) }) { Text("Accept") }
                    }
                }
            }
        }
    }
}
