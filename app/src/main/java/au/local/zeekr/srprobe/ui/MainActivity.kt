package au.local.zeekr.srprobe.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import au.local.zeekr.srprobe.logging.ReportExporter
import au.local.zeekr.srprobe.logging.ReportProvider
import au.local.zeekr.srprobe.model.Availability
import java.io.File

/**
 * Developer diagnostic screen (brief §5). Dark, large targets, no animations. Not a driving interface.
 */
class MainActivity : Activity() {

    private val vm by lazy { (application as ProbeApplication).vm }
    private val exporter by lazy { ReportExporter(this, vm) }
    private lateinit var status: LinearLayout
    private lateinit var busy: TextView
    private lateinit var logView: TextView
    private lateinit var binderToggle: Button
    private lateinit var captureStart: Button
    private lateinit var captureStop: Button
    private var lastExport: List<File> = emptyList()

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.decorView.setBackgroundColor(BG)
        val wide = resources.configuration.screenWidthDp >= 900
        val root = LinearLayout(this).apply {
            orientation = if (wide) LinearLayout.HORIZONTAL else LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(16))
        }

        val left = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        left.addView(text("7X SR Probe  v0.8.2", 30f, FG, bold = true))
        left.addView(TextView(this).apply {
            text = "SAFETY MODE   READ ONLY  ✓"
            textSize = 22f; setTextColor(Color.BLACK); typeface = Typeface.DEFAULT_BOLD
            setPadding(dp(16), dp(10), dp(16), dp(10))
            background = GradientDrawable().apply { setColor(OK); cornerRadius = dp(8).toFloat() }
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(8); bottomMargin = dp(8) }
        })
        left.addView(text("Diagnostic tool. Use parked. No vehicle settings are changed. No network.", 16f, DIM))
        busy = text("", 18f, WARN).also { left.addView(it) }
        status = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        left.addView(status)
        val leftScroll = ScrollView(this).apply { addView(left) }

        val right = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(if (wide) dp(24) else 0, 0, 0, 0) }
        right.addView(button("Run Safe Discovery") { vm.runSafeDiscovery() })
        right.addView(button("Refresh Known Signals") { vm.refreshSignals() })
        captureStart = button("Start Read-Only Capture (parked)") { startCapture(false) }.also { right.addView(it) }
        captureStop = button("Stop Capture") { vm.stopCapture() }.also { right.addView(it) }
        right.addView(button("Export Report") { export() })
        right.addView(button("Save Report To Folder / USB…") { pickFolder() })
        right.addView(button("Share Report…") { share() })
        right.addView(button("Show Summary (to photograph)") { showSummary() })
        right.addView(button("Show Report As QR Codes (scan with phone)") { showQr(0) })
        right.addView(button("Copy Report To Clipboard (in parts)") { copyNextPart() })
        right.addView(text("Optional (off by default, see READ_ONLY_AUDIT.md)", 16f, DIM).apply { setPadding(0, dp(16), 0, dp(4)) })
        binderToggle = button("") {
            vm.queryBinderDescriptors = !vm.queryBinderDescriptors
            render()
        }.also { right.addView(it) }
        right.addView(button("Read SDK-named ADAS ids once (parked)") { optInNamed(false) })
        right.addView(button("Subscribe to SR-object feed (parked)") { optInSrFeed(false) })
        right.addView(button("Query vehicle data provider (parked)") { optInProvider() })
        right.addView(button("Live surround preview (parked, nothing saved)") {
            if (vm.reader.isParked() == false) toast("Gear does not read P. Preview only runs parked.")
            else startActivity(Intent(this, SurroundPreviewActivity::class.java))
        })
        right.addView(button("List cameras (no images, parked)") {
            confirm("List cameras?", "Asks Android which cameras this app can see and their sizes. No camera is opened " +
                "and no picture or video is taken.") { toast("Listing…"); vm.listCameras { showText(exporter.cameraText()) } }
        })
        right.addView(text("Log", 18f, FG, bold = true).apply { setPadding(0, dp(16), 0, 0) })
        logView = text("", 13f, DIM).apply { typeface = Typeface.MONOSPACE; setTextIsSelectable(true) }
        right.addView(logView)
        val rightScroll = ScrollView(this).apply { addView(right) }

        if (wide) {
            root.addView(leftScroll, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1.4f))
            root.addView(rightScroll, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f))
        } else {
            root.addView(rightScroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
            root.addView(leftScroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1.4f))
        }
        setContentView(root)
        render()
    }

    override fun onResume() {
        super.onResume()
        vm.onChange = { render() }
        vm.recorder.listener = { runOnUiThread { renderLog() } }
        render()
    }

    override fun onPause() {
        super.onPause()
        vm.onChange = null
        vm.recorder.listener = null
    }

    // ------------------------------------------------------------------ actions

    private fun startCapture(confirmed: Boolean) {
        when (val r = vm.startCapture(confirmed)) {
            null -> toast("Capture running. Stop it before driving; v0.1 is a parked test.")
            "GEAR_UNKNOWN" -> confirm("Gear cannot be read", "Confirm the vehicle is in Park. Capture only records values.") { startCapture(true) }
            else -> toast(r)
        }
        render()
    }

    private fun optInNamed(confirmed: Boolean) {
        if (!confirmed) {
            confirm("Read SDK-named ADAS ids once?",
                "Reads each id the ECARX SDK itself names as ADAS/lane/target/traffic related, once, using the same " +
                    "getters as the known signals (getFunctionValue / getSensorEvent / getSensorLatestValue). " +
                    "No setters. Parked only. Skip this if you prefer to review the catalogue first.") { runNamed(true) }
            return
        }
        runNamed(true)
    }

    private fun runNamed(confirmedParked: Boolean) {
        when (val r = vm.readNamedConstants(false)) {
            null -> toast("Reading named ids…")
            "GEAR_UNKNOWN" -> confirm("Gear cannot be read", "Confirm the vehicle is in Park.") {
                vm.readNamedConstants(confirmedParked)?.let { toast(it) }
            }
            else -> toast(r)
        }
    }

    /** v0.8.1: the summary as QR codes, one per page, so a phone camera can read it as exact text. */
    private var qrParts: List<String> = emptyList()

    private fun showQr(index: Int) {
        if (index == 0 || qrParts.isEmpty()) qrParts = au.local.zeekr.srprobe.report.QrEncoder.chunks(exporter.summary(), 500)
        val i = index.coerceIn(0, qrParts.size - 1)
        val m = au.local.zeekr.srprobe.report.QrEncoder.encode(qrParts[i].toByteArray(Charsets.UTF_8))
        val quiet = 4
        val n = m.size + quiet * 2
        val px = IntArray(n * n) { k ->
            val y = k / n - quiet; val x = k % n - quiet
            if (y in m.indices && x in m.indices && m[y][x]) Color.BLACK else Color.WHITE
        }
        val bmp = android.graphics.Bitmap.createBitmap(px, n, n, android.graphics.Bitmap.Config.ARGB_8888)
        val side = (minOf(resources.displayMetrics.widthPixels, resources.displayMetrics.heightPixels) * 0.8f).toInt()
        val img = android.widget.ImageView(this).apply {
            setImageDrawable(android.graphics.drawable.BitmapDrawable(resources, bmp).apply { setFilterBitmap(false) })
            layoutParams = LinearLayout.LayoutParams(side, side)
            setBackgroundColor(Color.WHITE)
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL; setBackgroundColor(Color.WHITE)
            setPadding(dp(16), dp(16), dp(16), dp(16))
            addView(TextView(this@MainActivity).apply {
                text = "Code ${i + 1} of ${qrParts.size}: scan with your phone camera, copy the text, paste it in the chat"
                textSize = 18f; setTextColor(Color.BLACK)
            })
            addView(img)
        }
        val b = AlertDialog.Builder(this, android.R.style.Theme_Material_Light_NoActionBar_Fullscreen).setView(box)
            .setNegativeButton("Close", null)
        if (i > 0) b.setNeutralButton("Previous") { _, _ -> showQr(i - 1).let { } }
        if (i < qrParts.size - 1) b.setPositiveButton("Next") { _, _ -> showQr(i + 1).let { } }
        b.show()
    }

    /** v0.5: read-only query of the exported vehicle data provider. */
    private fun optInProvider() {
        confirm("Query the vehicle data provider?",
            "Reads content://com.zeekr.vehicle.data (exported by ZeekrVehicleService) with ContentResolver.query " +
                "only. Nothing is inserted, updated or deleted. Parked only.") {
            when (val r = vm.queryProvider(true) { showText(exporter.providerText()) }) {
                null -> toast("Querying…")
                else -> toast(r)
            }
        }
    }

    private fun showText(text: String) {
        val tv = TextView(this).apply {
            this.text = text; textSize = 15f; setTextColor(FG); typeface = Typeface.MONOSPACE; setTextIsSelectable(true)
            setPadding(dp(24), dp(16), dp(24), dp(16)); setBackgroundColor(BG)
        }
        AlertDialog.Builder(this, android.R.style.Theme_Material_NoActionBar_Fullscreen)
            .setView(ScrollView(this).apply { addView(tv) }).setPositiveButton("Close", null).show()
    }

    /** v0.4: subscribe to the live SR-object feed, parked only, read-only (register/unregister only). */
    private fun optInSrFeed(confirmed: Boolean) {
        if (!confirmed) {
            confirm("Subscribe to the SR-object feed?",
                "Connects to the car's AdcuService and calls registerSRObjectsObserver, the same read-only " +
                    "subscribe the factory 3D view uses, to receive surrounding-vehicle objects. Every send/set " +
                    "method is blocked by the guard. Parked only. It unsubscribes when you close the page.") { runSrFeed() }
            return
        }
        runSrFeed()
    }

    private fun runSrFeed() {
        when (val r = vm.startSrFeed(false)) {
            null -> showSrFeed()
            "GEAR_UNKNOWN" -> confirm("Gear cannot be read", "Confirm the vehicle is in Park.") {
                if (vm.startSrFeed(true) == null) showSrFeed()
            }
            else -> toast(r)
        }
    }

    /** Full-screen live view of the SR feed; refreshes while open and unsubscribes on close. */
    private fun showSrFeed() {
        val tv = TextView(this).apply {
            textSize = 15f; setTextColor(FG); typeface = Typeface.MONOSPACE; setTextIsSelectable(true)
            setPadding(dp(24), dp(16), dp(24), dp(16)); setBackgroundColor(BG)
        }
        val scroll = ScrollView(this).apply { addView(tv) }
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        val tick = object : Runnable {
            override fun run() {
                val f = vm.srFeed
                tv.text = buildString {
                    appendLine("SR-OBJECT FEED (read-only subscribe)")
                    appendLine("updates received: ${f?.updates?.get() ?: 0}")
                    appendLine()
                    appendLine(f?.outcome ?: "not started")
                    appendLine()
                    f?.last?.let { s ->
                        s.carPos?.let { appendLine("my car: ${it.fields}") }
                        appendLine("objects: ${s.objects.size}")
                        s.objects.take(30).forEachIndexed { i, o -> appendLine("  [$i] ${o.fields}") }
                        s.raw?.let { appendLine("payload fields: $it") }
                    }
                    appendLine()
                    appendLine("--- steps ---")
                    f?.steps?.forEach { appendLine(it) }
                }
                handler.postDelayed(this, 1000)
            }
        }
        handler.post(tick)
        AlertDialog.Builder(this, android.R.style.Theme_Material_NoActionBar_Fullscreen)
            .setView(scroll)
            .setPositiveButton("Close (unsubscribe)", null)
            .setOnDismissListener { handler.removeCallbacks(tick); vm.stopSrFeed() }
            .show()
    }

    private fun export(then: ((List<File>) -> Unit)? = null) {
        vm.runOnWorker {
            try {
                val files = exporter.writeAll()
                lastExport = files
                val where = runCatching { exporter.copyToDownloads(files) }.getOrElse { "Downloads copy failed: ${it.message}" }
                vm.recorder.log("Exported to ${exporter.outDir.absolutePath}; $where")
                runOnUiThread {
                    toast("Report exported. $where")
                    then?.invoke(files)
                }
            } catch (t: Throwable) {
                vm.recorder.log("Export failed: $t")
                runOnUiThread { toast("Export failed: ${t.message}") }
            }
        }
    }

    /** Full-screen, scrollable plain text of the findings that matter, sized to be readable in a photo. */
    private fun showSummary() {
        vm.runOnWorker {
            val text = try { exporter.summary() } catch (t: Throwable) { "Summary failed: $t" }
            runOnUiThread {
                val tv = TextView(this).apply {
                    this.text = text; textSize = 15f; setTextColor(FG); typeface = Typeface.MONOSPACE; setTextIsSelectable(true)
                    setPadding(dp(24), dp(16), dp(24), dp(16)); setBackgroundColor(BG)
                }
                val scroll = ScrollView(this).apply { addView(tv) }
                AlertDialog.Builder(this, android.R.style.Theme_Material_NoActionBar_Fullscreen)
                    .setView(scroll).setPositiveButton("Close", null).show()
            }
        }
    }

    private var clipParts: List<String> = emptyList()
    private var clipNext = 0

    /**
     * No file picker or USB needed: copies the Markdown report to the clipboard in pieces small enough for the
     * clipboard, one per press, so it can be pasted into a browser page or message. Nothing leaves the device
     * unless you paste it somewhere yourself. A new part list is built each time you press after the last part.
     */
    private fun copyNextPart() {
        vm.runOnWorker {
            try {
                if (clipNext == 0 || clipNext >= clipParts.size) {
                    clipParts = splitForClipboard(exporter.markdown())
                    clipNext = 0
                }
                val i = clipNext++
                val text = "[7X SR Probe report part ${i + 1}/${clipParts.size}]\n" + clipParts[i]
                runOnUiThread {
                    val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("srprobe-report", text))
                    toast("Copied part ${i + 1} of ${clipParts.size} (${text.length / 1000} KB). Paste it, then press again for " +
                        if (i + 1 < clipParts.size) "part ${i + 2}." else "nothing: that was the last part; pressing again restarts at part 1.")
                }
            } catch (t: Throwable) {
                runOnUiThread { toast("Copy failed: ${t.message}") }
            }
        }
    }

    private fun splitForClipboard(md: String, maxChars: Int = 120_000): List<String> {
        val parts = ArrayList<String>()
        val cur = StringBuilder()
        for (line in md.lineSequence()) {
            if (cur.length + line.length + 1 > maxChars && cur.isNotEmpty()) { parts += cur.toString(); cur.setLength(0) }
            cur.append(line.take(maxChars)).append('\n')
        }
        if (cur.isNotEmpty()) parts += cur.toString()
        return parts
    }

    private fun pickFolder() {
        try {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQ_TREE)
        } catch (t: Throwable) {
            toast("No folder picker on this head unit: ${t.message}")
        }
    }

    @Deprecated("Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val tree = data?.data
        if (requestCode != REQ_TREE || resultCode != RESULT_OK || tree == null) return
        export { files ->
            vm.runOnWorker {
                val msg = runCatching { exporter.copyToTree(tree, files) }.getOrElse { "Save failed: ${it.message}" }
                vm.recorder.log(msg)
                runOnUiThread { toast(msg) }
            }
        }
    }

    private fun share() = export { files ->
        val uris = ArrayList(files.filter { it.extension != "zip" }.map { ReportProvider.uriFor(it) })
        val send = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "*/*"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            putExtra(Intent.EXTRA_SUBJECT, "7X SR Probe report")
            clipData = ClipData.newRawUri("report", uris[0]).apply { uris.drop(1).forEach { addItem(ClipData.Item(it)) } }
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        try {
            startActivity(Intent.createChooser(send, "Share report"))
        } catch (t: Throwable) {
            toast("No share target available: ${t.message}")
        }
    }

    // ------------------------------------------------------------------ rendering

    private fun render() {
        val b = vm.busy
        busy.text = if (b != null) "Working: $b…" else ""
        binderToggle.text = "Binder interface names: ${if (vm.queryBinderDescriptors) "ON" else "OFF"}"
        val capturing = vm.capture?.running == true
        captureStart.isEnabled = !capturing
        captureStop.isEnabled = capturing

        status.removeAllViews()
        val env = vm.environment
        header("Environment")
        val android = env.firstOrNull { it.title.startsWith("Android") }?.rows?.toMap() ?: emptyMap()
        val props = env.firstOrNull { it.title.startsWith("Platform") }?.rows?.toMap() ?: emptyMap()
        row("Android", android["Android release"]?.let { "$it (SDK ${android["SDK level"]})" } ?: "—")
        row("Reported device", android["Model"]?.let { "${android["Manufacturer"]} $it" } ?: "—")
        row("Real build id", props["ro.build.display.id"] ?: "—")
        row("Board platform", props["ro.board.platform"] ?: "—")
        row("Display", env.firstOrNull { it.title == "Displays" }?.rows?.firstOrNull()?.second ?: "—")
        row("Package", packageName)

        header("Platform APIs")
        val st = vm.ecarx.status
        row("ECARX", when {
            st.car == Availability.AVAILABLE -> "CONNECTED"
            st.car == Availability.NOT_RUN -> if (vm.ecarx.classPresent()) "PRESENT (not connected)" else "NOT FOUND"
            else -> st.car.name
        }, color(st.car))
        row("Vehicle interface", st.function.name, color(st.function))
        row("Sensor manager", st.sensor.name, color(st.sensor))
        row("Car info", st.carInfo.name, color(st.carInfo))

        header("Known signals")
        if (vm.signals.isEmpty()) row("—", "Run Safe Discovery")
        vm.signals.forEach { s -> row(s.label, s.decodedValue ?: s.availability.name, color(s.availability)) }

        header("Discovery")
        row("Relevant packages", "${vm.packages?.relevant?.size ?: "—"} of ${vm.packages?.totalVisible ?: "—"}")
        row("Relevant services", "${vm.services?.relevant?.size ?: "—"} of ${vm.services?.totalServices ?: "—"}")
        row("Vendor classes reflected", "${vm.apis.size}")
        row("Relevant constants", "${vm.apis.sumOf { a -> a.fields.count { it.constantValue != null } }} read, ${vm.namedConstants.size} ADAS-named")
        row("Sources scanned (names)", "${vm.dexScans.size}, ${vm.dexScans.sumOf { it.matchingClasses.size }} relevant class names")
        row("Opt-in named reads", if (vm.namedReads.isEmpty()) "not run" else "${vm.namedReads.count { it.availability == Availability.AVAILABLE }} real of ${vm.namedReads.size}")
        row("Capture", if (capturing) "RUNNING, ${vm.recorder.eventsWritten} events" else "stopped, ${vm.recorder.eventsWritten} events")
        row("Unknown event sources", "${vm.capture?.unknownCallbacks?.size ?: 0}")
        if (vm.errors.isNotEmpty()) row("Errors", "${vm.errors.size} (see report)", WARN)
        renderLog()
    }

    private fun renderLog() {
        logView.text = vm.recorder.logLines().takeLast(40).joinToString("\n")
    }

    private fun header(t: String) = status.addView(text(t, 20f, ACCENT, bold = true).apply { setPadding(0, dp(18), 0, dp(4)) })

    private fun row(k: String, v: String, c: Int = FG) {
        val l = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(3), 0, dp(3)) }
        l.addView(text(k, 17f, DIM), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        l.addView(text(v, 17f, c).apply { gravity = Gravity.END }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.2f))
        status.addView(l)
    }

    private fun color(a: Availability) = when (a) {
        Availability.AVAILABLE -> OK
        Availability.UNAVAILABLE, Availability.NOT_RUN -> DIM
        Availability.API_NOT_PRESENT -> FG
        Availability.PERMISSION_DENIED, Availability.ERROR -> WARN
    }

    private fun text(t: String, size: Float, c: Int, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = size; setTextColor(c); if (bold) typeface = Typeface.DEFAULT_BOLD
    }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label; textSize = 19f; isAllCaps = false; setTextColor(FG); minHeight = dp(72)
        background = GradientDrawable().apply { setColor(PANEL); cornerRadius = dp(10).toFloat(); setStroke(dp(1), BORDER) }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) }
        setOnClickListener { onClick() }
    }

    private fun confirm(title: String, msg: String, yes: () -> Unit) {
        AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle(title).setMessage(msg)
            .setPositiveButton("Vehicle is in Park") { _, _ -> yes() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    companion object {
        private const val REQ_TREE = 41
        private val BG = Color.rgb(0x0E, 0x11, 0x16)
        private val PANEL = Color.rgb(0x1A, 0x1F, 0x27)
        private val BORDER = Color.rgb(0x2C, 0x34, 0x40)
        private val FG = Color.rgb(0xE8, 0xED, 0xF2)
        private val DIM = Color.rgb(0x8A, 0x96, 0xA3)
        private val ACCENT = Color.rgb(0x35, 0xC2, 0xA0)
        private val OK = Color.rgb(0x35, 0xC2, 0xA0)
        private val WARN = Color.rgb(0xF2, 0xA5, 0x3A)
    }
}
