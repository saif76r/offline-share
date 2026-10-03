package com.offlineshare.app.storage

import android.content.ContentValues
import android.content.Context
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Pure-Kotlin filename rules (unit tested) - mirrors the Windows server's sanitize_filename. */
object Names {
    private val bad = Regex("[<>:\"/\\\\|?*\\u0000-\\u001f]")
    private val reserved = setOf("CON", "PRN", "AUX", "NUL") + (1..9).map { "COM$it" } + (1..9).map { "LPT$it" }

    fun sanitize(raw: String): String {
        var n = raw.replace("\\", "/").substringAfterLast('/')
        n = bad.replace(n, "_").trim(' ', '.')
        if (n.isEmpty()) n = "file"
        if (n.substringBeforeLast('.').uppercase() in reserved) n = "_$n"
        if (n.length > 150) { val ext = n.substringAfterLast('.', ""); val dot = if (ext.isEmpty()) "" else ".$ext"; n = n.take(150 - dot.length) + dot }
        return n
    }

    /** "document.pdf" -> "document (1).pdf" -> "document (2).pdf" until [exists] says it is free. */
    fun unique(name: String, exists: (String) -> Boolean): String {
        if (!exists(name)) return name
        val stem = name.substringBeforeLast('.', name)
        val ext = if (name.contains('.')) "." + name.substringAfterLast('.') else ""
        var i = 1
        while (exists("$stem ($i)$ext")) i++
        return "$stem ($i)$ext"
    }
}

object Storage {
    const val RELATIVE = "Download/OfflineShare/Received"

    /** Partial downloads live here (app-private) so a dropped connection can resume. */
    fun partDir(ctx: Context): File =
        File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "OfflineShare/Received/.partial").apply { mkdirs() }

    fun partFile(ctx: Context, fileId: String): File = partDir(ctx).resolve("$fileId.part")

    /** Moves a verified file into Downloads/OfflineShare/Received. Never overwrites. Returns the final name. */
    fun publishReceived(ctx: Context, part: File, rawName: String): String {
        val resolver = ctx.contentResolver
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val name = Names.unique(Names.sanitize(rawName)) { candidate ->
            resolver.query(collection, arrayOf(MediaStore.Downloads._ID),
                "${MediaStore.Downloads.DISPLAY_NAME}=? AND ${MediaStore.Downloads.RELATIVE_PATH} LIKE ?",
                arrayOf(candidate, "$RELATIVE%"), null)?.use { it.moveToFirst() } ?: false
        }
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase()) ?: "application/octet-stream"
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name); put(MediaStore.Downloads.MIME_TYPE, mime)
            put(MediaStore.Downloads.RELATIVE_PATH, "$RELATIVE/"); put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri = resolver.insert(collection, values) ?: error("Cannot create file in Downloads")
        resolver.openOutputStream(uri)!!.use { out -> part.inputStream().use { it.copyTo(out, 1 shl 20) } }
        resolver.update(uri, ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }, null, null)
        part.delete()
        return name
    }
}

data class HistoryItem(val name: String, val size: Long, val direction: String, val device: String,
                       val status: String, val sha256: String, val ts: Long, val durationMs: Long)

class HistoryStore(ctx: Context) {
    private val file = File(ctx.filesDir, "history.json")
    @Synchronized fun add(i: HistoryItem) {
        val arr = load().apply { put(JSONObject().put("name", i.name).put("size", i.size).put("dir", i.direction).put("dev", i.device)
            .put("status", i.status).put("sha", i.sha256).put("ts", i.ts).put("dur", i.durationMs)) }
        val keep = JSONArray(); for (k in maxOf(0, arr.length() - 500) until arr.length()) keep.put(arr.get(k))
        file.writeText(keep.toString())
    }
    @Synchronized fun all(): List<HistoryItem> {
        val a = load()
        return (a.length() - 1 downTo 0).map { a.getJSONObject(it).let { j -> HistoryItem(j.getString("name"), j.getLong("size"), j.getString("dir"),
            j.getString("dev"), j.getString("status"), j.getString("sha"), j.getLong("ts"), j.getLong("dur")) } }
    }
    private fun load() = try { JSONArray(file.readText()) } catch (e: Exception) { JSONArray() }
}
