package au.local.zeekr.srprobe.platform

import android.content.Context
import android.net.Uri
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard

/**
 * v0.5: read-only query of the vehicle data provider ZeekrVehicleService exports
 * (READ_ONLY_AUDIT.md section G). Only ContentResolver.query and getType go through ReadOnlyGuard,
 * on the root URI and on URIs the vendor's own code names (found as dex strings by discovery).
 * Private-looking columns are dropped and VIN-like values redacted before anything is kept.
 */
object ProviderProbe {

    data class UriResult(val uri: String, val type: String?, val columns: List<String>, val rows: List<String>, val count: Int, val error: String?)

    private const val MAX_URIS = 40
    private const val MAX_ROWS = 5

    fun run(context: Context, vendorUris: List<String>): List<UriResult> {
        val resolver = context.contentResolver
        val uris = (listOf("content://com.zeekr.vehicle.data") + vendorUris)
            .map { it.trimEnd('/') }
            .filter { Uri.parse(it).authority in ReadOnlyGuard.PROVIDER_AUTHORITIES }
            .distinct().take(MAX_URIS)
        return uris.map { query(resolver, it) }
    }

    private fun query(resolver: android.content.ContentResolver, s: String): UriResult {
        val uri = Uri.parse(s)
        val type = runCatching { ReadOnlyGuard.providerType(resolver, uri) }.getOrNull()
        return try {
            val c = ReadOnlyGuard.queryProvider(resolver, uri)
                ?: return UriResult(s, type, emptyList(), emptyList(), 0, "query returned null")
            c.use { cur ->
                val cols = cur.columnNames.toList()
                val rows = ArrayList<String>()
                while (rows.size < MAX_ROWS && cur.moveToNext()) {
                    rows += cols.indices.joinToString(", ") { i ->
                        val name = cols[i]
                        if (Terms.isPrivateKey(name)) "$name=[dropped]"
                        else "$name=" + (runCatching { cur.getString(i) }.getOrNull()?.let { Terms.redact(it).take(120) } ?: "null")
                    }
                }
                UriResult(s, type, cols, rows, cur.count, null)
            }
        } catch (t: Throwable) {
            UriResult(s, type, emptyList(), emptyList(), 0, ReadOnlyGuard.describe(t))
        }
    }
}
