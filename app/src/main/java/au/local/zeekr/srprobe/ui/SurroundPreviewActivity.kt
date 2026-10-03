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
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.BLACK); gravity = Gravity.CENTER_HORIZONTAL
            addView(status); addView(image); addView(close)
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
            }
            frames++
            val n = frames
            main.post {
                bitmap = bmp; image.setImageBitmap(bmp)
                status.text = "Surround preview (parked, nothing saved) · frame $n · front / rear / left / right"
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
            lastClosed = SystemClock.elapsedRealtime()
            t?.quitSafely()
        }
        if (h != null) h.post(work) else work.run()
    }

    private var resumed = false
    @Volatile private var opening = false

    companion object {
        private val LABELS = arrayOf("FRONT", "REAR", "LEFT", "RIGHT")
        private const val REOPEN_GAP_MS = 3000L
        @Volatile private var lastClosed = 0L
    }
}
