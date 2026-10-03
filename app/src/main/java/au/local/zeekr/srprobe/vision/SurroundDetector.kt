package au.local.zeekr.srprobe.vision

import android.content.Context
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * v0.8.5: finds cars, trucks, buses, motorbikes, bicycles and people in each surround view.
 * Runs Google's COCO SSD MobileNet (assets/detect.tflite) with TensorFlow Lite on frames held in memory.
 * Results are only drawn on screen; nothing is stored or sent, and no vehicle call is made.
 */
class SurroundDetector(context: Context) {

    data class Hit(val label: String, val score: Float, val left: Float, val top: Float, val right: Float, val bottom: Float)

    private val interpreter: Interpreter
    private val labels: List<String>
    private val input = ByteBuffer.allocateDirect(SIZE * SIZE * 3).order(ByteOrder.nativeOrder())
    private val boxes = Array(1) { Array(10) { FloatArray(4) } }
    private val classes = Array(1) { FloatArray(10) }
    private val scores = Array(1) { FloatArray(10) }
    private val count = FloatArray(1)

    init {
        val fd = context.assets.openFd("detect.tflite")
        val model = FileInputStream(fd.fileDescriptor).channel.map(FileChannel.MapMode.READ_ONLY, fd.startOffset, fd.declaredLength)
        interpreter = Interpreter(model, Interpreter.Options().setNumThreads(4))
        labels = context.assets.open("labelmap.txt").bufferedReader().readLines()
    }

    /**
     * Detects in one square view of a YUV_420_888 frame. (x0, y0) is the view's top-left in the frame, side its size.
     * Returned boxes are 0..1 within that view.
     */
    fun detect(yb: ByteBuffer, ub: ByteBuffer, vb: ByteBuffer, yRow: Int, uvRow: Int, uvPix: Int,
               x0: Int, y0: Int, side: Int, minScore: Float = 0.45f): List<Hit> {
        input.rewind()
        for (j in 0 until SIZE) {
            val sy = y0 + j * side / SIZE
            for (i in 0 until SIZE) {
                val sx = x0 + i * side / SIZE
                val y = yb.get(sy * yRow + sx).toInt() and 0xff
                val uvi = (sy / 2) * uvRow + (sx / 2) * uvPix
                val u = (ub.get(uvi).toInt() and 0xff) - 128
                val v = (vb.get(uvi).toInt() and 0xff) - 128
                input.put((y + 1.402f * v).toInt().coerceIn(0, 255).toByte())
                input.put((y - 0.344f * u - 0.714f * v).toInt().coerceIn(0, 255).toByte())
                input.put((y + 1.772f * u).toInt().coerceIn(0, 255).toByte())
            }
        }
        input.rewind()
        val outputs = HashMap<Int, Any>()
        outputs[0] = boxes; outputs[1] = classes; outputs[2] = scores; outputs[3] = count
        interpreter.runForMultipleInputsOutputs(arrayOf<Any>(input), outputs)
        val out = ArrayList<Hit>()
        for (k in 0 until minOf(10, count[0].toInt())) {
            val cls = classes[0][k].toInt()
            val label = labels.getOrNull(cls + 1) ?: continue
            if (label !in WANTED || scores[0][k] < minScore) continue
            val b = boxes[0][k] // ymin, xmin, ymax, xmax
            out += Hit(label, scores[0][k], b[1].coerceIn(0f, 1f), b[0].coerceIn(0f, 1f), b[3].coerceIn(0f, 1f), b[2].coerceIn(0f, 1f))
        }
        return out
    }

    fun close() = interpreter.close()

    companion object {
        const val SIZE = 300
        val WANTED = setOf("car", "truck", "bus", "motorcycle", "bicycle", "person")
    }
}
