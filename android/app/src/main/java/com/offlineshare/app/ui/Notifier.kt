package com.offlineshare.app.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

class Notifier(private val ctx: Context) {
    private val ch = "transfers"
    init {
        (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(NotificationChannel(ch, "File transfers", NotificationManager.IMPORTANCE_LOW))
    }

    fun progress(id: Int, name: String, percent: Int, upload: Boolean) = post(id,
        NotificationCompat.Builder(ctx, ch).setSmallIcon(if (upload) android.R.drawable.stat_sys_upload else android.R.drawable.stat_sys_download)
            .setContentTitle("OfflineShare").setContentText((if (upload) "Sending " else "Receiving ") + name)
            .setProgress(100, percent, false).setOngoing(true).setOnlyAlertOnce(true))

    fun done(id: Int, name: String) = post(id,
        NotificationCompat.Builder(ctx, ch).setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Transfer Complete ✓").setContentText(name).setAutoCancel(true))

    fun failed(id: Int, name: String, why: String) = post(id,
        NotificationCompat.Builder(ctx, ch).setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("Transfer interrupted").setContentText("$name - $why").setAutoCancel(true))

    private fun post(id: Int, b: NotificationCompat.Builder) {
        try { NotificationManagerCompat.from(ctx).notify(id, b.build()) } catch (_: SecurityException) { /* notifications denied */ }
    }
}
