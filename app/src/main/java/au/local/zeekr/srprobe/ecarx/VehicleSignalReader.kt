package au.local.zeekr.srprobe.ecarx

import android.os.SystemClock
import au.local.zeekr.srprobe.model.Availability
import au.local.zeekr.srprobe.model.ReadKind
import au.local.zeekr.srprobe.model.VehicleSignal
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.lang.reflect.Method

/**
 * Reads values through the four getters proven on the reference 7X (brief §10). Only getters; the
 * id passed in is always from [KnownSignal] or (opt-in) an SDK-declared constant, never a guessed number.
 */
class VehicleSignalReader(private val ecarx: EcarxAvailability) {

    data class Raw(val availability: Availability, val value: Any?, val error: String?)

    fun read(kind: ReadKind, id: Int, zone: Int): Raw {
        val (method: Method?, target: Any?, args: Array<Any>) = when (kind) {
            ReadKind.FUNCTION -> Triple(ecarx.getFunctionValue, ecarx.function, arrayOf<Any>(id))
            ReadKind.FUNCTION_ZONE -> Triple(ecarx.getFunctionValueZoned, ecarx.function, arrayOf<Any>(id, zone))
            ReadKind.SENSOR_EVENT -> Triple(ecarx.getSensorEvent, ecarx.sensor, arrayOf<Any>(id))
            ReadKind.SENSOR_VALUE -> Triple(ecarx.getSensorLatestValue, ecarx.sensor, arrayOf<Any>(id))
            ReadKind.CAR_INFO_INT -> Triple(ecarx.getCarInfoInt, ecarx.carInfo, arrayOf<Any>(id))
        }
        if (method == null || target == null) return Raw(Availability.API_NOT_PRESENT, null, null)
        return try {
            // VEHICLE CALL: ICarFunction.getFunctionValue(id[, zone]) / ISensor.getSensorEvent(type) /
            // ISensor.getSensorLatestValue(type) / ICarInfo.getCarInfoInt(id). Getters returning the value the
            // car service already holds. They take an id and return a number; they have no write path.
            val v = ReadOnlyGuard.invoke(method, target, *args)
            Raw(if (KnownSignal.isPlaceholder(v)) Availability.UNAVAILABLE else Availability.AVAILABLE, v, null)
        } catch (t: Throwable) {
            Raw(EcarxAvailability.avail(t), null, ReadOnlyGuard.describe(t))
        }
    }

    fun readKnown(s: KnownSignal): VehicleSignal {
        val r = read(s.kind, s.id, s.zone)
        return VehicleSignal(
            key = s.name,
            label = s.label,
            kind = s.kind,
            id = s.id,
            zone = s.zone,
            availability = r.availability,
            rawValue = KnownSignal.rawString(r.value),
            decodedValue = s.decode(r.value),
            note = r.error ?: s.note,
            readAtElapsedNs = SystemClock.elapsedRealtimeNanos()
        )
    }

    fun readAllKnown(): List<VehicleSignal> = KnownSignal.values().map { readKnown(it) }

    /** True only when gear can be read and is P. Used to gate capture start and the opt-in step. */
    fun isParked(): Boolean? {
        val r = read(KnownSignal.GEAR.kind, KnownSignal.GEAR.id, 0)
        if (r.availability != Availability.AVAILABLE) return null
        return (r.value as? Number)?.toInt() == 0x00200230
    }
}
