package au.local.zeekr.srprobe.ui

import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.SystemClock
import android.util.Size
import android.view.Gravity
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import au.local.zeekr.srprobe.safety.ReadOnlyGuard

/**
 * v0.8.2: live surround-camera preview, parked only (READ_ONLY_AUDIT.md section H, owner approved 2026-10-03).
 *
 * Opens the camera that offers the stacked 4-view stream, receives frames into memory, and draws them as a
 * 2x2 grid on screen. No frame is recorded, saved, encoded or sent anywhere; nothing is written to the camera
 * beyond the standard preview request. The camera closes when this screen is left or the gear leaves P.
 */
class SurroundPreviewActivity : Activity() {

    private lateinit var image: ImageView
    private lateinit var topView: ImageView
    private lateinit var status: TextView
    private val main = Handler(Looper.getMainLooper())
    private var thread: HandlerThread? = null
    private var bg: Handler? = null
    private var device: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    @Volatile private var lastFrame = 0L
    @Volatile private var frames = 0
    private var bitmap: Bitmap? = null
    private var pixels: IntArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { textSize = 18f; setTextColor(Color.WHITE); setPadding(24, 16, 24, 8) }
        image = ImageView(this).apply {
            scaleType = ImageView.ScaleType.FIT_CENTER
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        val close = Button(this).apply { text = "Close (camera off)"; textSize = 18f; setOnClickListener { finish() } }
        topView = ImageView(this).apply {
            scaleType = ImageView.ScaleType.FIT_CENTER
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 0.6f)
        }
        image.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 1f)
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
            addView(image); addView(topView)
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.BLACK); gravity = Gravity.CENTER_HORIZONTAL
            addView(status); addView(row); addView(close)
        })
        status.text = "Surround preview: starting…"
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        if ((application as ProbeApplication).vm.reader.isParked() == false) { status.text = "Gear is not P. Preview only runs parked."; return }
        if (checkSelfPermission(android.Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.CAMERA), 7); return
        }
        start()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) { if (resumed) start() }
        else status.text = "Camera permission was not granted, so nothing was opened."
    }

    override fun onPause() { resumed = false; stop(); super.onPause() }

    private fun pickCamera(cm: CameraManager): Pair<String, Size>? {
        var best: Pair<String, Size>? = null
        for (id in cm.cameraIdList) {
            ReadOnlyGuard.count("camera:getCameraCharacteristics()")
            val map = cm.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: continue
            val tall = map.getOutputSizes(ImageFormat.YUV_420_888)?.firstOrNull { it.height >= it.width * 3 }
            if (tall != null) return id to tall
            if (best == null && cm.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_EXTERNAL)
                best = id to (map.getOutputSizes(ImageFormat.YUV_420_888)?.maxByOrNull { it.width * it.height } ?: continue)
        }
        return best
    }

    private fun start() {
        if (device != null || opening) return
        val since = SystemClock.elapsedRealtime() - lastClosed
        if (since < REOPEN_GAP_MS) {
            status.text = "Waiting a moment before reopening the camera…"
            main.postDelayed({ if (!isFinishing && resumed) start() }, REOPEN_GAP_MS - since)
            return
        }
        opening = true
        try {
            val cm = getSystemService(CameraManager::class.java)
            val (id, size) = pickCamera(cm) ?: run { status.text = "No surround (tall) stream found."; return }
            thread = HandlerThread("srprobe-cam").also { it.start() }
            bg = Handler(thread!!.looper)
            val r = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2)
            reader = r
            r.setOnImageAvailableListener({ rd -> onFrame(rd, size) }, bg)
            status.text = "Opening camera $id (${size.width}x${size.height}) — preview only, nothing is saved"
            ReadOnlyGuard.count("camera:openCamera(preview only)")
            cm.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(d: CameraDevice) {
                    device = d; opening = false
                    if (!resumed) { closeQuietly(); return }
                    @Suppress("DEPRECATION")
                    d.createCaptureSession(listOf(r.surface), object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(s: CameraCaptureSession) {
                            session = s
                            val req = d.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply { addTarget(r.surface) }.build()
                            s.setRepeatingRequest(req, null, bg)
                            main.post(watchGear)
                        }
                        override fun onConfigureFailed(s: CameraCaptureSession) { main.post { status.text = "Camera session failed to configure." } }
                    }, bg)
                }
                // The car may take the camera back at any time (its own 360 view, parking aid). We let it go and do not retry.
                override fun onDisconnected(d: CameraDevice) { device = d; opening = false; closeQuietly(); main.post { status.text = "The car took the camera back. Close and reopen this screen to try again." } }
                override fun onError(d: CameraDevice, error: Int) { device = d; opening = false; closeQuietly(); main.post { status.text = "Camera error $error. Not retrying." } }
            }, bg)
        } catch (t: Throwable) {
            opening = false
            status.text = "Could not open the camera: ${ReadOnlyGuard.describe(t)}"
        }
    }

    private val watchGear = object : Runnable {
        override fun run() {
            if (device == null) return
            if ((application as ProbeApplication).vm.reader.isParked() == false) {
                stop(); status.text = "Gear left P: camera closed."; return
            }
            main.postDelayed(this, 1000)
        }
    }

    /** Converts one frame to a 2x2 grid (half resolution, colour) in memory and shows it. Max ~8 per second. */
    private fun onFrame(rd: ImageReader, size: Size) {
        val img = rd.acquireLatestImage() ?: return
        try {
            val now = SystemClock.elapsedRealtime()
            if (now - lastFrame < 125) return
            lastFrame = now
            val tiles = if (size.height >= size.width * 3) 4 else 1
            // Stacked stream: four square views separated by 5 thin bands (1280x5140 = 4x1280 + 5x4px).
            val band = if (tiles == 4 && size.height > size.width * 4) (size.height - size.width * 4) / 5 else 0
            val tileH = if (band > 0) size.width else size.height / tiles
            val sw = size.width / 2; val sh = tileH / 2
            val cols = if (tiles == 4) 2 else 1
            val outW = sw * cols; val outH = sh * (if (tiles == 4) 2 else 1)
            val px = pixels?.takeIf { it.size == outW * outH } ?: IntArray(outW * outH).also { pixels = it }
            val y = img.planes[0]; val u = img.planes[1]; val v = img.planes[2]
            val yb = y.buffer; val ub = u.buffer; val vb = v.buffer
            val yRow = y.rowStride; val uvRow = u.rowStride; val uvPix = u.pixelStride
            for (t in 0 until tiles) {
                val ox = (t % cols) * sw; val oy = (t / cols) * sh
                for (j in 0 until sh) {
                    val sy = band + t * (tileH + band) + j * 2
                    for (i in 0 until sw) {
                        val sx = i * 2
                        val Y = (yb.get(sy * yRow + sx).toInt() and 0xff)
                        val uvi = (sy / 2) * uvRow + (sx / 2) * uvPix
                        val U = (ub.get(uvi).toInt() and 0xff) - 128
                        val V = (vb.get(uvi).toInt() and 0xff) - 128
                        val r = (Y + 1.402f * V).toInt().coerceIn(0, 255)
                        val g = (Y - 0.344f * U - 0.714f * V).toInt().coerceIn(0, 255)
                        val b = (Y + 1.772f * U).toInt().coerceIn(0, 255)
                        px[(oy + j) * outW + ox + i] = (0xff shl 24) or (r shl 16) or (g shl 8) or b
                    }
                }
            }
            val bmp = Bitmap.createBitmap(px, outW, outH, Bitmap.Config.ARGB_8888).copy(Bitmap.Config.ARGB_8888, true)
            if (tiles == 4) {
                val c = android.graphics.Canvas(bmp)
                val paint = android.graphics.Paint().apply { color = Color.WHITE; textSize = sh / 12f; isFakeBoldText = true; setShadowLayer(4f, 0f, 0f, Color.BLACK) }
                for (t in 0 until 4) c.drawText(LABELS[t], (t % cols) * sw + sw / 30f, (t / cols) * sh + sh / 9f, paint)
                // v0.8.6: detection on three flat sub-views cut from each fisheye view (in memory, on screen only).
                val det = detector ?: if (detectorError == null) runCatching { au.local.zeekr.srprobe.vision.SurroundDetector(this) }
                    .onFailure { detectorError = ReadOnlyGuard.describe(it) }.getOrNull().also { detector = it } else null
                if (det != null && band > 0) {
                    val G = au.local.zeekr.srprobe.vision.FisheyeGeometry
                    val luts = subLuts ?: Array(4) { cam -> G.subViews(cam).map { sv -> sv to G.lut(sv) } }.also { subLuts = it }
                    val t0 = SystemClock.elapsedRealtime()
                    val box = android.graphics.Paint().apply { style = android.graphics.Paint.Style.STROKE; strokeWidth = sh / 140f; isAntiAlias = true }
                    val tag = android.graphics.Paint().apply { textSize = sh / 20f; isFakeBoldText = true; setShadowLayer(4f, 0f, 0f, Color.BLACK) }
                    val scale = sw.toFloat() / G.SIDE
                    val found = ArrayList<Placed>()
                    for (cam in 0 until 4) {
                        val ox = (cam % cols) * sw; val oy = (cam / cols) * sh
                        for ((sv, lut) in luts[cam]) {
                            for (h in det.detect(yb, ub, vb, yRow, uvRow, uvPix, lut, band + cam * (tileH + band))) {
                                val col = colourFor(h.label)
                                box.color = col; tag.color = col
                                // Box outline traced back onto the fisheye view (it bends with the lens).
                                val path = android.graphics.Path()
                                val pts = ArrayList<DoubleArray>()
                                for (i in 0..8) pts += doubleArrayOf(h.left + (h.right - h.left) * i / 8.0, h.top.toDouble())
                                for (i in 0..8) pts += doubleArrayOf(h.right.toDouble(), h.top + (h.bottom - h.top) * i / 8.0)
                                for (i in 0..8) pts += doubleArrayOf(h.right - (h.right - h.left) * i / 8.0, h.bottom.toDouble())
                                for (i in 0..8) pts += doubleArrayOf(h.left.toDouble(), h.bottom - (h.bottom - h.top) * i / 8.0)
                                pts.forEachIndexed { i, q ->
                                    val f = G.fisheyePixel(G.ray(sv, q[0], q[1]))
                                    val px2 = ox + f[0].toFloat() * scale; val py2 = oy + f[1].toFloat() * scale
                                    if (i == 0) path.moveTo(px2, py2) else path.lineTo(px2, py2)
                                }
                                path.close(); c.drawPath(path, box)
                                val topLeft = G.fisheyePixel(G.ray(sv, h.left.toDouble(), h.top.toDouble()))
                                c.drawText("${h.label} ${(h.score * 100).toInt()}%", ox + topLeft[0].toFloat() * scale, oy + topLeft[1].toFloat() * scale - 4f, tag)
                                // Ground position from the bottom-centre of the box.
                                G.ground(cam, G.ray(sv, (h.left + h.right) / 2.0, h.bottom.toDouble()))?.let { g ->
                                    found += Placed(h.label, h.score, g[0], g[1])
                                }
                            }
                        }
                    }
                    placed = dedupe(found)
                    detectNote = "${placed.size} objects, ${SystemClock.elapsedRealtime() - t0} ms"
                    val td = topDown(placed)
                    main.post { topView.setImageBitmap(td) }
                }
            }
            frames++
            val n = frames
            main.post {
                bitmap = bmp; image.setImageBitmap(bmp)
                status.text = "Surround preview (parked, nothing saved) · frame $n · detection: " + (detectorError?.let { "unavailable ($it)" } ?: detectNote)
            }
        } catch (t: Throwable) {
            main.post { status.text = "Frame error: ${ReadOnlyGuard.describe(t)}" }
        } finally {
            img.close()
        }
    }

    /** Closes on the camera thread: CameraDevice.close() can block for seconds inside the camera service. */
    private fun stop() {
        main.removeCallbacks(watchGear)
        closeQuietly()
    }

    private fun closeQuietly() {
        val s = session; val d = device; val r = reader; val t = thread; val h = bg
        session = null; device = null; reader = null; thread = null; bg = null
        if (s == null && d == null && r == null && t == null) return
        val work = Runnable {
            runCatching { s?.close() }; runCatching { d?.close() }; runCatching { r?.close() }
            runCatching { detector?.close() }; detector = null
            lastClosed = SystemClock.elapsedRealtime()
            t?.quitSafely()
        }
        if (h != null) h.post(work) else work.run()
    }

    @Volatile private var detector: au.local.zeekr.srprobe.vision.SurroundDetector? = null
    @Volatile private var detectorError: String? = null
    @Volatile private var detectNote = "starting"
    private var subLuts: Array<List<Pair<au.local.zeekr.srprobe.vision.FisheyeGeometry.SubView, IntArray>>>? = null
    private var placed: List<Placed> = emptyList()

    /** An object placed on the ground around the car: x forward, y right, metres. */
    data class Placed(val label: String, val score: Float, val x: Double, val y: Double)

    private fun colourFor(label: String) = when (label) {
        "person", "bicycle" -> Color.YELLOW; "truck", "bus" -> Color.rgb(255, 140, 0); else -> Color.GREEN
    }

    /** Overlapping sub-views can see one object twice: keep the stronger of two same-kind hits within 1.5 m. */
    private fun dedupe(all: List<Placed>): List<Placed> {
        val out = ArrayList<Placed>()
        for (p in all.sortedByDescending { it.score }) {
            val person = p.label == "person" || p.label == "bicycle"
            if (out.none { q -> (q.label == "person" || q.label == "bicycle") == person && Math.hypot(q.x - p.x, q.y - p.y) < 1.5 }) out += p
        }
        return out
    }

    /** Tesla-style top-down view: our car in the middle, each object drawn where it was placed (approximate). */
    private fun topDown(objs: List<Placed>): Bitmap {
        val w = 520; val h = 900; val ppm = 22f // pixels per metre: about +-20 m ahead/behind, +-12 m to the sides
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val c = android.graphics.Canvas(bmp)
        c.drawColor(Color.rgb(18, 20, 24))
        val cx = w / 2f; val cy = h / 2f
        val p = android.graphics.Paint().apply { isAntiAlias = true }
        p.style = android.graphics.Paint.Style.STROKE; p.color = Color.rgb(50, 55, 62); p.strokeWidth = 2f
        for (r in intArrayOf(5, 10, 15, 20)) c.drawCircle(cx, cy, r * ppm, p)
        p.style = android.graphics.Paint.Style.FILL
        p.color = Color.rgb(90, 160, 255)
        c.drawRoundRect(android.graphics.RectF(cx - 0.97f * ppm, cy - 2.4f * ppm, cx + 0.97f * ppm, cy + 2.4f * ppm), 12f, 12f, p)
        for (o in objs) {
            val px = cx + o.y.toFloat() * ppm; val py = cy - o.x.toFloat() * ppm
            p.color = colourFor(o.label)
            when (o.label) {
                "person", "bicycle" -> c.drawCircle(px, py, 0.4f * ppm, p)
                "truck", "bus" -> c.drawRoundRect(android.graphics.RectF(px - 1.25f * ppm, py - 4f * ppm, px + 1.25f * ppm, py + 4f * ppm), 8f, 8f, p)
                else -> c.drawRoundRect(android.graphics.RectF(px - 0.95f * ppm, py - 2.3f * ppm, px + 0.95f * ppm, py + 2.3f * ppm), 10f, 10f, p)
            }
        }
        p.color = Color.LTGRAY; p.textSize = 22f
        c.drawText("Top-down (distances approximate)", 12f, 30f, p)
        return bmp
    }

    private var resumed = false
    @Volatile private var opening = false

    companion object {
        private val LABELS = arrayOf("FRONT", "REAR", "LEFT", "RIGHT")
        private const val REOPEN_GAP_MS = 3000L
        @Volatile private var lastClosed = 0L
    }
}
