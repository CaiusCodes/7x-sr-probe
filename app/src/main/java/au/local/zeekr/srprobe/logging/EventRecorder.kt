package au.local.zeekr.srprobe.logging

import android.content.Context
import android.os.SystemClock
import android.util.Log
import au.local.zeekr.srprobe.model.ProbeEvent
import org.json.JSONObject
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/**
 * Local-only event log. Two streams:
 *  - probe log lines (human-readable, shown in the UI and appended to the report);
 *  - capture events (one JSON object per line in srprobe-events.jsonl, brief §12 schema).
 *
 * Change-based: [record] drops an event whose (source, api, eventId) value equals the last one written.
 * Nothing here leaves the device; exporting is an explicit user action in ReportExporter.
 */
class EventRecorder(context: Context) {

    private val dir = File(context.filesDir, "srprobe").apply { mkdirs() }
    val eventsFile = File(dir, "srprobe-events.jsonl")
    private val logLines = ArrayDeque<String>()
    private val lastValue = HashMap<String, String?>()
    private var writer: BufferedWriter? = null
    private val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US)

    @Volatile var eventsWritten = 0L; private set
    @Volatile var eventsSuppressed = 0L; private set
    private val sourceCounts = HashMap<String, Long>()

    var listener: ((String) -> Unit)? = null

    fun now(): String = synchronized(iso) { iso.format(Date()) }

    fun log(line: String) {
        val stamped = "${now().substring(11, 23)}  $line"
        Log.i(TAG, line)
        synchronized(logLines) {
            logLines.addLast(stamped)
            while (logLines.size > MAX_LOG_LINES) logLines.removeFirst()
        }
        listener?.invoke(stamped)
    }

    fun logLines(): List<String> = synchronized(logLines) { logLines.toList() }

    @Synchronized
    fun startCapture(append: Boolean) {
        writer?.close()
        if (!append) {
            eventsFile.delete()
            eventsWritten = 0
            eventsSuppressed = 0
            sourceCounts.clear()
        }
        lastValue.clear()
        writer = BufferedWriter(FileWriter(eventsFile, true))
    }

    @Synchronized
    fun stopCapture() {
        writer?.flush()
        writer?.close()
        writer = null
    }

    val capturing: Boolean @Synchronized get() = writer != null

    /** Write one event if its value changed since the last event with the same key. */
    @Synchronized
    fun record(source: String, api: String, eventId: String?, rawType: String?, rawValue: String?, decoded: String?): Boolean {
        val w = writer ?: return false
        val key = "$source|$api|$eventId"
        if (lastValue.containsKey(key) && lastValue[key] == rawValue) {
            eventsSuppressed++
            return false
        }
        lastValue[key] = rawValue
        val e = ProbeEvent(SystemClock.elapsedRealtimeNanos(), now(), source, api, eventId, rawType, rawValue, decoded)
        w.write(toJson(e).toString())
        w.newLine()
        eventsWritten++
        sourceCounts[source] = (sourceCounts[source] ?: 0L) + 1
        if (eventsWritten % 50 == 0L) w.flush()
        return true
    }

    @Synchronized
    fun flush() {
        writer?.flush()
    }

    @Synchronized
    fun sourceCountsSnapshot(): Map<String, Long> = HashMap(sourceCounts)

    companion object {
        private const val TAG = "SRProbe"
        private const val MAX_LOG_LINES = 2000

        fun toJson(e: ProbeEvent): JSONObject = JSONObject().apply {
            put("monotonicNs", e.monotonicNs)
            put("timestamp", e.timestamp)
            put("source", e.source)
            put("api", e.api)
            put("eventId", e.eventId ?: JSONObject.NULL)
            put("rawType", e.rawType ?: JSONObject.NULL)
            put("rawValue", e.rawValue ?: JSONObject.NULL)
            put("decodedValue", e.decodedValue ?: JSONObject.NULL)
        }
    }
}
