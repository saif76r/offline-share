package com.offlineshare.app

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.LaunchedEffect
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.offlineshare.app.ui.MainViewModel
import com.offlineshare.app.ui.OfflineShareApp
import com.offlineshare.app.ui.OfflineShareTheme

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            OfflineShareTheme {
                val perms = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { vm.discover() }
                val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { vm.stage(it) }   // Storage Access Framework
                val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let(vm::handleQr) }
                LaunchedEffect(Unit) {
                    val need = mutableListOf(Manifest.permission.CAMERA)
                    if (Build.VERSION.SDK_INT >= 33) need += listOf(Manifest.permission.NEARBY_WIFI_DEVICES, Manifest.permission.POST_NOTIFICATIONS)
                    else need += Manifest.permission.ACCESS_FINE_LOCATION
                    perms.launch(need.toTypedArray())
                }
                OfflineShareApp(vm,
                    onPickFiles = { pick.launch(arrayOf("*/*")) },
                    onScanQr = { scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scan the QR code on the laptop").setBeepEnabled(false).setOrientationLocked(false)) })
            }
        }
    }
}
