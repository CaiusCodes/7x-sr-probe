package au.local.zeekr.srprobe.ecarx

import android.content.Context
import android.os.SystemClock
import au.local.zeekr.srprobe.model.Availability
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * ECARX adapt-API presence and connection (brief §9).
 *
 * Evidence (dts88/zeekr-shortcut-car docs/zeekr-platform-notes.md and telemetry/EcarxSource.java):
 * on a 7X in App Lab, ecarx.adaptapi.impl.jar is on BOOTCLASSPATH, Car.create(context) returns in ~1 s
 * without any permission, and getICarFunction()/getSensorManager()/getCarInfoManager() return managers whose
 * get* methods read cached vehicle values. NOT yet observed on the Australian 7X.
 *
 * Every vehicle call below goes through [ReadOnlyGuard.invoke]. Each call site is commented.
 */
class EcarxAvailability {

    data class Status(
        val classPresent: Boolean,
        val car: Availability,
        val function: Availability,
        val sensor: Availability,
        val carInfo: Availability,
        val detail: String,
        val connectMs: Long
    )

    var car: Any? = null; private set
    var function: Any? = null; private set
    var sensor: Any? = null; private set
    var carInfo: Any? = null; private set

    var getFunctionValue: Method? = null; private set
    var getFunctionValueZoned: Method? = null; private set
    var getSensorEvent: Method? = null; private set
    var getSensorLatestValue: Method? = null; private set
    var getCarInfoInt: Method? = null; private set

    @Volatile var status: Status = Status(false, Availability.NOT_RUN, Availability.NOT_RUN, Availability.NOT_RUN, Availability.NOT_RUN, "not run", 0)
        private set

    /** Presence only: Class.forName with initialize=false runs no static initialiser. */
    fun classPresent(): Boolean =
        runCatching { Class.forName(ReadOnlyGuard.ECARX_CAR_CLASS, false, javaClass.classLoader) }.isSuccess

    /** Must run off the main thread (Car.create took ~1 s on the reference car). Idempotent. */
    @Synchronized
    fun connect(context: Context): Status {
        if (car != null) return status
        val start = SystemClock.elapsedRealtime()
        val carClass = try {
            Class.forName(ReadOnlyGuard.ECARX_CAR_CLASS, false, javaClass.classLoader)
        } catch (t: Throwable) {
            status = Status(false, Availability.API_NOT_PRESENT, Availability.API_NOT_PRESENT, Availability.API_NOT_PRESENT,
                Availability.API_NOT_PRESENT, "${ReadOnlyGuard.ECARX_CAR_CLASS} not on this head unit", 0)
            return status
        }
        val create = carClass.methods.firstOrNull {
            it.name == "create" && Modifier.isStatic(it.modifiers) && it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == Context::class.java
        }
        if (create == null) {
            status = Status(true, Availability.API_NOT_PRESENT, Availability.NOT_RUN, Availability.NOT_RUN, Availability.NOT_RUN,
                "Car class present but no static create(Context)", 0)
            return status
        }
        // VEHICLE CALL: Car.create(Context) — static factory returning the adapt-API Car facade. Connects this
        // process to the ECARX car service as a client. Reads only; no vehicle state is written.
        val c = try {
            ReadOnlyGuard.invoke(create, null, context.applicationContext)
        } catch (t: Throwable) {
            status = Status(true, avail(t), Availability.NOT_RUN, Availability.NOT_RUN, Availability.NOT_RUN,
                "Car.create failed: ${ReadOnlyGuard.describe(t)}", SystemClock.elapsedRealtime() - start)
            return status
        }
        car = c
        if (c == null) {
            status = Status(true, Availability.UNAVAILABLE, Availability.NOT_RUN, Availability.NOT_RUN, Availability.NOT_RUN,
                "Car.create returned null", SystemClock.elapsedRealtime() - start)
            return status
        }

        // VEHICLE CALL: Car.getICarFunction() — no-arg getter returning the function-value manager.
        val fn = getManager(c, "getICarFunction")
        // VEHICLE CALL: Car.getSensorManager() — no-arg getter returning the sensor manager.
        val sn = getManager(c, "getSensorManager")
        // VEHICLE CALL: Car.getCarInfoManager() — no-arg getter returning the static car-info manager.
        val ci = getManager(c, "getCarInfoManager")
        function = fn.first; sensor = sn.first; carInfo = ci.first

        function?.let {
            getFunctionValue = Reflect.findPublic(it, "getFunctionValue", Int::class.javaPrimitiveType!!)
            getFunctionValueZoned = Reflect.findPublic(it, "getFunctionValue", Int::class.javaPrimitiveType!!, Int::class.javaPrimitiveType!!)
        }
        sensor?.let {
            getSensorEvent = Reflect.findPublic(it, "getSensorEvent", Int::class.javaPrimitiveType!!)
            getSensorLatestValue = Reflect.findPublic(it, "getSensorLatestValue", Int::class.javaPrimitiveType!!)
        }
        carInfo?.let { getCarInfoInt = Reflect.findPublic(it, "getCarInfoInt", Int::class.javaPrimitiveType!!) }

        val ms = SystemClock.elapsedRealtime() - start
        val detail = "connected in $ms ms; car=${c.javaClass.name}; " +
            "function=${function?.javaClass?.name ?: fn.second}; sensor=${sensor?.javaClass?.name ?: sn.second}; " +
            "carInfo=${carInfo?.javaClass?.name ?: ci.second}; getters: fn=${getFunctionValue != null} fnZone=${getFunctionValueZoned != null} " +
            "sensorEvent=${getSensorEvent != null} sensorValue=${getSensorLatestValue != null} carInfoInt=${getCarInfoInt != null}"
        status = Status(true, Availability.AVAILABLE, fn.third, sn.third, ci.third, detail, ms)
        return status
    }

    private fun getManager(car: Any, name: String): Triple<Any?, String, Availability> {
        val m = Reflect.findPublic(car, name) ?: return Triple(null, "no $name()", Availability.API_NOT_PRESENT)
        return try {
            val r = ReadOnlyGuard.invoke(m, car)
            Triple(r, if (r == null) "$name() returned null" else "ok", if (r == null) Availability.UNAVAILABLE else Availability.AVAILABLE)
        } catch (t: Throwable) {
            Triple(null, "$name() failed: ${ReadOnlyGuard.describe(t)}", avail(t))
        }
    }

    companion object {
        fun avail(t: Throwable): Availability {
            var e: Throwable? = t
            while (e != null) {
                if (e is SecurityException && e !is ReadOnlyGuard.ReadOnlyViolation) return Availability.PERMISSION_DENIED
                e = e.cause
            }
            return Availability.ERROR
        }
    }
}
