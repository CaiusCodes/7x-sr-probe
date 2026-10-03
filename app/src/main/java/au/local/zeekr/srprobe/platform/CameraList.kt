package au.local.zeekr.srprobe.platform

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.io.File

/**
 * v0.8: lists the cameras this app can see (READ_ONLY_AUDIT.md section H). Uses only
 * CameraManager.getCameraIdList and getCameraCharacteristics, which describe a camera without opening it.
 * openCamera is never called, no CAMERA permission is requested, and no image is captured.
 */
object CameraList {

    data class Cam(val id: String, val lines: List<String>)
    data class Result(val hasCameraPermission: Boolean, val cameras: List<Cam>, val devVideo: List<String>, val error: String?,
                      val detector: String = au.local.zeekr.srprobe.vision.DetectorRuntime.check())

    fun run(context: Context): Result {
        val perm = context.checkSelfPermission(android.Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        val dev = runCatching { File("/dev").list()?.filter { it.startsWith("video") }?.sorted() }.getOrNull().orEmpty()
        return try {
            val cm = context.getSystemService(CameraManager::class.java) ?: return Result(perm, emptyList(), dev, "no CameraManager")
            ReadOnlyGuard.count("camera:getCameraIdList()")
            val ids = cm.cameraIdList.toList()
            Result(perm, ids.map { describe(cm, it) }, dev, null)
        } catch (t: Throwable) {
            Result(perm, emptyList(), dev, ReadOnlyGuard.describe(t))
        }
    }

    private fun describe(cm: CameraManager, id: String): Cam = try {
        ReadOnlyGuard.count("camera:getCameraCharacteristics()")
        val c = cm.getCameraCharacteristics(id)
        val out = ArrayList<String>()
        val facing = when (c.get(CameraCharacteristics.LENS_FACING)) {
            CameraCharacteristics.LENS_FACING_FRONT -> "front"; CameraCharacteristics.LENS_FACING_BACK -> "back"
            CameraCharacteristics.LENS_FACING_EXTERNAL -> "external"; else -> "unknown"
        }
        val level = when (c.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)) {
            0 -> "LIMITED"; 1 -> "FULL"; 2 -> "LEGACY"; 3 -> "LEVEL_3"; 4 -> "EXTERNAL"; else -> "?"
        }
        out += "facing=$facing level=$level pixels=${c.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE)}"
        val map = c.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        if (map != null) {
            val yuv = map.getOutputSizes(ImageFormat.YUV_420_888)?.sortedByDescending { it.width * it.height }?.take(4)
            out += "yuv sizes: ${yuv?.joinToString() ?: "none"}"
            out += "formats: ${map.outputFormats.joinToString { "0x" + Integer.toHexString(it) }}"
        }
        val caps = c.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES)
        if (caps != null) out += "capabilities: ${caps.joinToString()}"
        val phys = runCatching { c.physicalCameraIds }.getOrNull()
        if (!phys.isNullOrEmpty()) out += "physical ids: ${phys.joinToString()}"
        Cam(id, out)
    } catch (t: Throwable) {
        Cam(id, listOf("error: ${ReadOnlyGuard.describe(t)}"))
    }
}
