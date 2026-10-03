package au.local.zeekr.srprobe.vision

/**
 * v0.8.4: checks that the on-device detection runtime (TensorFlow Lite) loads on the head unit.
 * Loading the native library and reading its version touches nothing outside this app.
 */
object DetectorRuntime {
    fun check(): String = try {
        "TensorFlow Lite " + org.tensorflow.lite.TensorFlowLite.runtimeVersion() + " loaded"
    } catch (t: Throwable) {
        "not available: " + t.javaClass.simpleName + (t.message?.let { ": " + it.take(160) } ?: "")
    }
}
