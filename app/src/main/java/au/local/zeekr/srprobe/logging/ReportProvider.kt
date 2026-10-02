package au.local.zeekr.srprobe.logging

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File

/**
 * Minimal read-only provider so the share sheet can read exported report files.
 * Not exported; other apps only get access to a specific URI through a temporary grant on the share intent.
 * Serves files from filesDir/srprobe/export only. insert/update/delete are refused.
 */
class ReportProvider : ContentProvider() {

    private fun fileFor(uri: Uri): File? {
        val dir = File(context!!.filesDir, "srprobe/export")
        val name = uri.lastPathSegment ?: return null
        val f = File(dir, name)
        return if (f.parentFile?.canonicalPath == dir.canonicalPath && f.exists()) f else null
    }

    override fun onCreate() = true

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        if (mode != "r") throw SecurityException("read-only")
        return ParcelFileDescriptor.open(fileFor(uri) ?: return null, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? {
        val f = fileFor(uri) ?: return null
        return MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)).apply { addRow(arrayOf<Any>(f.name, f.length())) }
    }

    override fun getType(uri: Uri): String = when (uri.lastPathSegment?.substringAfterLast('.')) {
        "md" -> "text/markdown"; "json" -> "application/json"; "jsonl" -> "application/x-ndjson"; "zip" -> "application/zip"
        else -> "application/octet-stream"
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException("read-only")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException("read-only")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException("read-only")

    companion object {
        const val AUTHORITY = "au.local.zeekr.srprobe.reports"
        fun uriFor(f: File): Uri = Uri.parse("content://$AUTHORITY/${f.name}")
    }
}
