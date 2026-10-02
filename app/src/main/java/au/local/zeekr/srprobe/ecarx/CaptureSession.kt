package au.local.zeekr.srprobe.ecarx

import android.os.Handler
import android.os.HandlerThread
import au.local.zeekr.srprobe.logging.EventRecorder
import au.local.zeekr.srprobe.model.ReadKind
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.concurrent.ConcurrentHashMap

/**
 * Read-only capture (brief §12). Records changes only.
 *
 *  - Polls [KnownSignal] floats every 200 ms (with a per-signal change threshold) and discrete values every
 *    1 s, plus any opt-in named ids that returned a real value.
 *  - Subscribes to change callbacks for the known ids using the two registration methods proven on the
 *    reference 7X. Our proxy listener records every callback it receives, including callback methods we do
 *    not recognise ("unknown event sources"), with raw arguments.
 *
 * Known quirk from the reference project: ISensor listeners appear impossible to unregister (re-registering
 * duplicates callbacks), so sensor listeners are registered once per process and ignored after Stop.
 * Function watchers are unregistered on Stop.
 */
class CaptureSession(
    private val ecarx: EcarxAvailability,
    private val reader: VehicleSignalReader,
    private val recorder: EventRecorder,
    private val extraIds: List<Triple<ReadKind, Int, String>>
) {
    private var thread: HandlerThread? = null
    @Volatile private var handler: Handler? = null
    @Volatile var running = false; private set
    private var functionWatcher: Any? = null
    private var functionIds = IntArray(0)
    private val lastFloat = HashMap<KnownSignal, Float>()

    val unknownCallbacks: MutableMap<String, Long> = ConcurrentHashMap()
    var subscribeSummary = ""; private set

    fun start() {
        if (running) return
        running = true
        recorder.startCapture(append = false)
        thread = HandlerThread("srprobe-capture").also { it.start() }
        handler = Handler(thread!!.looper)
        handler!!.post {
            subscribeSummary = subscribe()
            recorder.log("Capture started. $subscribeSummary")
            handler?.post(floatPoll)
            handler?.post(discretePoll)
        }
        active = this
    }

    fun stop() {
        if (!running) return
        running = false
        if (active === this) active = null
        val h = handler
        handler = null
        h?.removeCallbacksAndMessages(null)
        h?.post { unregisterFunctions(); recorder.stopCapture() }
        thread?.quitSafely()
        thread = null
        recorder.log("Capture stopped. events=${recorder.eventsWritten} suppressed(identical)=${recorder.eventsSuppressed}")
    }

    // ------------------------------------------------------------------ polling

    private val floatPoll = object : Runnable {
        override fun run() {
            if (!running) return
            for (s in KnownSignal.values()) {
                if (!s.isFloat) continue
                val r = reader.read(s.kind, s.id, s.zone)
                val v = (r.value as? Number)?.toFloat()
                if (v != null) {
                    val prev = lastFloat[s]
                    if (prev != null && Math.abs(prev - v) < threshold(s)) continue
                    lastFloat[s] = v
                }
                recorder.record("ecarx-poll", "${s.kind}", hex(s.id), r.value?.javaClass?.simpleName,
                    KnownSignal.rawString(r.value) ?: r.availability.name, s.decode(r.value))
            }
            handler?.postDelayed(this, FLOAT_POLL_MS)
        }
    }

    private val discretePoll = object : Runnable {
        override fun run() {
            if (!running) return
            for (s in KnownSignal.values()) {
                if (s.isFloat) continue
                val r = reader.read(s.kind, s.id, s.zone)
                recorder.record("ecarx-poll", "${s.kind}", hex(s.id) + if (s.zone != 0) "@" + hex(s.zone) else "",
                    r.value?.javaClass?.simpleName, KnownSignal.rawString(r.value) ?: r.availability.name, s.decode(r.value))
            }
            for ((kind, id, name) in extraIds) {
                val r = reader.read(kind, id, 0)
                recorder.record("ecarx-poll-optin", "$kind $name", hex(id), r.value?.javaClass?.simpleName,
                    KnownSignal.rawString(r.value) ?: r.availability.name, null)
            }
            recorder.flush()
            handler?.postDelayed(this, DISCRETE_POLL_MS)
        }
    }

    private fun threshold(s: KnownSignal): Float = when (s) {
        KnownSignal.SPEED -> 0.05f       // m/s
        KnownSignal.STEERING -> 0.003f   // rad (~0.17°)
        else -> 0.5f                     // pedal depths
    }

    // ------------------------------------------------------------------ subscriptions

    private fun subscribe(): String {
        val parts = ArrayList<String>()
        val fn = ecarx.function
        if (fn != null) {
            val ids = KnownSignal.values().filter { it.kind == ReadKind.FUNCTION || it.kind == ReadKind.FUNCTION_ZONE }
                .map { it.id }.distinct()
            functionIds = ids.toIntArray()
            val byArray = Reflect.findWithTrailingInterface(fn, "registerFunctionValueWatcher", IntArray::class.java)
            val byOne = Reflect.findWithTrailingInterface(fn, "registerFunctionValueWatcher", Int::class.javaPrimitiveType!!)
            val any = byArray ?: byOne
            if (any == null) {
                parts += "functions: no registerFunctionValueWatcher"
            } else {
                val proxy = proxyFor(any.parameterTypes[1], "function")
                try {
                    if (byArray != null) {
                        // VEHICLE CALL: ICarFunction.registerFunctionValueWatcher(int[], listener) — asks the car
                        // service to call our listener when these ids change. Delivers values; changes nothing.
                        ReadOnlyGuard.invoke(byArray, fn, functionIds, proxy)
                        parts += "functions: watching ${functionIds.size}"
                    } else {
                        var ok = 0
                        for (id in functionIds) {
                            // VEHICLE CALL: ICarFunction.registerFunctionValueWatcher(int, listener) — per-id variant.
                            runCatching { ReadOnlyGuard.invoke(byOne!!, fn, id, proxy) }.onSuccess { ok++ }
                        }
                        parts += "functions: watching $ok/${functionIds.size} (per id)"
                    }
                    functionWatcher = proxy
                } catch (t: Throwable) {
                    parts += "functions: refused (${ReadOnlyGuard.describe(t)})"
                }
            }
        }
        val sn = ecarx.sensor
        if (sn != null) {
            val reg = Reflect.findWithLeadingInterface(sn, "registerListener", Int::class.javaPrimitiveType!!)
            if (reg == null) {
                parts += "sensors: no registerListener"
            } else synchronized(SENSOR_LOCK) {
                if (sensorProxy == null) sensorProxy = proxyFor(reg.parameterTypes[0], "sensor")
                var added = 0
                for (s in KnownSignal.values()) {
                    if (s.kind != ReadKind.SENSOR_EVENT || s.id in sensorTypesRegistered) continue
                    try {
                        // VEHICLE CALL: ISensor.registerListener(listener, type) — subscribe to one sensor event
                        // type. Once per process (see class comment). Delivers values; changes nothing.
                        ReadOnlyGuard.invoke(reg, sn, sensorProxy, s.id)
                        sensorTypesRegistered += s.id
                        added++
                    } catch (t: Throwable) {
                        recorder.log("registerListener(${hex(s.id)}) refused: ${ReadOnlyGuard.describe(t)}")
                    }
                }
                parts += "sensors: ${sensorTypesRegistered.size} listening (+$added)"
            }
        }
        return parts.joinToString("; ")
    }

    private fun unregisterFunctions() {
        val fn = ecarx.function ?: return
        val w = functionWatcher ?: return
        functionWatcher = null
        try {
            val one = Reflect.findWithOnlyInterface(fn, "unregisterFunctionValueWatcher")
            val withIds = Reflect.findWithTrailingInterface(fn, "unregisterFunctionValueWatcher", IntArray::class.java)
            val perId = Reflect.findWithTrailingInterface(fn, "unregisterFunctionValueWatcher", Int::class.javaPrimitiveType!!)
            // VEHICLE CALL: ICarFunction.unregisterFunctionValueWatcher(...) — removes our own listener.
            when {
                one != null -> ReadOnlyGuard.invoke(one, fn, w)
                withIds != null -> ReadOnlyGuard.invoke(withIds, fn, functionIds, w)
                perId != null -> functionIds.forEach { ReadOnlyGuard.invoke(perId, fn, it, w) }
            }
        } catch (t: Throwable) {
            recorder.log("unregisterFunctionValueWatcher failed: ${ReadOnlyGuard.describe(t)}")
        }
    }

    private fun proxyFor(iface: Class<*>, label: String): Any =
        Proxy.newProxyInstance(CaptureSession::class.java.classLoader, arrayOf(iface), Listener(label))

    /** Records every callback. Returns neutral defaults for any non-void callback. */
    private class Listener(private val label: String) : InvocationHandler {
        override fun invoke(proxy: Any, method: Method, args: Array<out Any?>?): Any? {
            when (method.name) {
                "toString" -> return "SRProbe.$label-listener"
                "hashCode" -> return System.identityHashCode(proxy)
                "equals" -> return args?.size == 1 && proxy === args[0]
            }
            val target = active
            if (target != null && target.running) {
                val h = target.handler
                val a = args?.toList() ?: emptyList()
                h?.post { target.onCallback(label, method.name, a) }
            }
            return when (method.returnType) {
                java.lang.Boolean.TYPE -> false
                Integer.TYPE, java.lang.Short.TYPE, java.lang.Byte.TYPE -> 0
                java.lang.Long.TYPE -> 0L
                java.lang.Float.TYPE -> 0f
                java.lang.Double.TYPE -> 0.0
                Character.TYPE -> '\u0000'
                else -> null
            }
        }
    }

    private fun onCallback(label: String, name: String, args: List<Any?>) {
        val known = name == "onFunctionValueChanged" || name == "onSensorEventChanged" || name == "onSensorValueChanged"
        val id = (args.getOrNull(0) as? Int)?.let { hex(it) }
        val eventId = if (name == "onFunctionValueChanged" && args.size >= 3) "$id@${hex(args[1] as? Int ?: 0)}" else id
        val value = if (known) args.lastOrNull() else null
        if (known) {
            recorder.record("ecarx-callback-$label", name, eventId, value?.javaClass?.simpleName, KnownSignal.rawString(value), null)
        } else {
            unknownCallbacks.merge("$label.$name(${args.size} args)", 1L) { a, b -> a + b }
            recorder.record("ecarx-callback-unknown", "$label.$name", id, args.joinToString { it?.javaClass?.simpleName ?: "null" },
                args.joinToString { KnownSignal.rawString(it) ?: "null" }.take(2000), null)
        }
    }

    companion object {
        const val FLOAT_POLL_MS = 200L
        const val DISCRETE_POLL_MS = 1000L
        @Volatile private var active: CaptureSession? = null
        private val SENSOR_LOCK = Any()
        private var sensorProxy: Any? = null
        private val sensorTypesRegistered = HashSet<Int>()
        fun hex(v: Int) = "0x" + String.format("%08X", v)
    }
}
