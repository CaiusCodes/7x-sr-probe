package au.local.zeekr.srprobe.ecarx

import au.local.zeekr.srprobe.model.ReadKind
import au.local.zeekr.srprobe.model.SignalTrust

/**
 * The fixed list of vehicle values v0.1 reads. Nothing outside this table is read unless the user runs the
 * separate opt-in "named ADAS constants" step (see SensorDiscovery).
 *
 * Provenance: ids, units and meanings come from the public project dts88/zeekr-shortcut-car
 * (app/src/main/java/com/kooo/evcam/telemetry/Signal.java and docs/zeekr-platform-notes.md, read 2026-10-02),
 * which reports them as observed on a right-hand-drive Zeekr 7X inside App Lab. The market of that car is
 * not stated. None of these has been observed on the Australian 7X yet: that is what v0.1 is for.
 *
 * The ADAS rows are settings switches (feature on/off), not live interventions or detections.
 */
enum class KnownSignal(
    val label: String,
    val kind: ReadKind,
    val id: Int,
    val zone: Int,
    val trust: SignalTrust,
    val format: Format,
    val note: String
) {
    // ---- Driving
    SPEED("Vehicle speed", ReadKind.SENSOR_VALUE, 0x00100100, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.MPS_TO_KMH, "sensor value in m/s"),
    GEAR("Gear", ReadKind.SENSOR_EVENT, 0x00200200, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.GEAR, "P=0x00200230 R=…40 N=…10 D=…20"),
    STEERING("Steering angle", ReadKind.SENSOR_VALUE, 0x00101000, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.RAD_TO_DEG, "radians, left positive"),
    BRAKE_PEDAL("Brake pedal", ReadKind.FUNCTION, 0x20317A00, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "0 released / 1 pressed"),
    BRAKE_DEPTH("Brake depth", ReadKind.SENSOR_VALUE, 0x00101300, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.FLOAT, "unit unknown; ~44 = floored"),
    ACCELERATOR("Accelerator", ReadKind.SENSOR_VALUE, 0x00101400, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.FLOAT, "0–100 %"),
    IGNITION("Ignition state", ReadKind.FUNCTION, 0x20259000, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.HEX, "ACC=0x00200104 ON=…05 DRIVING=…07"),
    AUTO_HOLD_ACTIVE("Auto hold holding", ReadKind.FUNCTION, 0x20320600, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "1 while auto hold is holding"),

    // ---- Indicators
    INDICATOR_STATUS("Indicator status", ReadKind.FUNCTION, 0x2A091500, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.INDICATOR, "0 off 1 left 2 right 3 hazard; steady"),
    LEFT_INDICATOR("Left indicator lamp", ReadKind.FUNCTION, 0x21051100, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "blinks 0/1"),
    RIGHT_INDICATOR("Right indicator lamp", ReadKind.FUNCTION, 0x21051200, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "blinks 0/1"),

    // ---- Lights / environment
    LOW_BEAM("Low beam", ReadKind.FUNCTION, 0x21050100, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, ""),
    DAY_NIGHT("Day / night", ReadKind.SENSOR_EVENT, 0x00201000, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.DAY_NIGHT, "0x00201001 day, …02 night"),

    // ---- Body. Zone 0x1 = ROW_1_DRVR; on the reference RHD car that was the right front door.
    DOOR_ZONE_1("Door zone 0x1 (driver on RHD)", ReadKind.FUNCTION_ZONE, 0x21020100, 0x1, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "0 closed 1 open"),
    DOOR_ZONE_4("Door zone 0x4 (front passenger on RHD)", ReadKind.FUNCTION_ZONE, 0x21020100, 0x4, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "0 closed 1 open"),
    DRIVER_SIDE("Driver side (car info)", ReadKind.CAR_INFO_INT, 0x00100300, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.HEX, "0x00100301 left, 0x00100302 right"),

    // ---- Factory UI state
    AVM_SHOWN("Factory 360/AVM shown", ReadKind.FUNCTION, 0x2031FE00, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.HEX, "1 showing 360, 2 not shown, 0 side-view popup?"),
    FACTORY_POPUP("Factory camera popup", ReadKind.FUNCTION, 0x2031B200, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "1 while 360 or side popup is up"),
    PARK_ASSIST("Park assist", ReadKind.FUNCTION, 0x23030100, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, ""),

    // ---- ADAS feature switches (settings state, NOT live detections)
    AEB_SWITCH("AEB switch", ReadKind.FUNCTION, 0x20070E00, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "setting"),
    FCW_LEVEL("FCW sensitivity", ReadKind.FUNCTION, 0x200E0200, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.HEX, "0 off, 0x200E0201–03 low/med/high"),
    LDW_SWITCH("LDW switch", ReadKind.FUNCTION, 0x28084100, 0, SignalTrust.UNVERIFIED, Format.ON_OFF, "setting; read 255 elsewhere"),
    LKA_SWITCH("LKA switch", ReadKind.FUNCTION, 0x20070100, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "setting"),
    BSD_SWITCH("Blind-spot (BSD) switch", ReadKind.FUNCTION, 0x28081600, 0, SignalTrust.UNVERIFIED, Format.ON_OFF, "setting, not occupancy"),
    RCW_SWITCH("Rear collision warning switch", ReadKind.FUNCTION, 0x20071000, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "setting"),
    LCA_SWITCH("Lane change assist switch", ReadKind.FUNCTION, 0x20070300, 0, SignalTrust.OBSERVED_ELSEWHERE, Format.ON_OFF, "setting"),
    LCC_SWITCH("Lane centring (LCC) switch", ReadKind.FUNCTION, 0x28085B00, 0, SignalTrust.UNVERIFIED, Format.ON_OFF, "candidate only"),
    DRIVE_PILOT("Drive pilot / ACC candidate", ReadKind.FUNCTION, 0x28070400, 0, SignalTrust.UNVERIFIED, Format.HEX, "SETTING_FUNC_DRIVE_PILOT; read 255 parked elsewhere");

    enum class Format { ON_OFF, HEX, FLOAT, MPS_TO_KMH, RAD_TO_DEG, GEAR, INDICATOR, DAY_NIGHT }

    val isFloat: Boolean get() = kind == ReadKind.SENSOR_VALUE

    companion object {
        /** ECARX integer placeholders: 255 unknown, 254 none, 253 error; -1 and -65535 also seen. */
        fun isIntPlaceholder(v: Int) = v == 255 || v == 254 || v == 253 || v == -1 || v == -65535

        /** Float placeholders: NaN, 255, -65535, and tiny non-zero values meaning "no data". 0 is a real 0. */
        fun isFloatPlaceholder(v: Float) = v.isNaN() || v == 255f || v == -65535f || (v != 0f && Math.abs(v) < 1e-6f)

        fun isPlaceholder(raw: Any?): Boolean = when (raw) {
            null -> true
            is Float -> isFloatPlaceholder(raw)
            is Double -> isFloatPlaceholder(raw.toFloat())
            is Number -> isIntPlaceholder(raw.toInt())
            else -> false
        }

        fun rawString(raw: Any?): String? = when (raw) {
            null -> null
            is Int -> "$raw (0x${Integer.toHexString(raw)})"
            is Float, is Double -> raw.toString()
            is IntArray -> raw.joinToString(prefix = "[", postfix = "]")
            is FloatArray -> raw.joinToString(prefix = "[", postfix = "]")
            else -> raw.toString()
        }
    }

    /** Human-readable decoding. Returns null for placeholders. Never used for anything but display. */
    fun decode(raw: Any?): String? {
        if (raw == null || isPlaceholder(raw)) return null
        val n = raw as? Number ?: return raw.toString()
        return when (format) {
            Format.ON_OFF -> when (n.toInt()) { 0 -> "OFF"; 1 -> "ON"; else -> "raw ${n.toInt()}" }
            Format.HEX -> "0x${Integer.toHexString(n.toInt())}"
            Format.FLOAT -> "%.2f".format(java.util.Locale.US, n.toFloat())
            Format.MPS_TO_KMH -> "%.1f km/h".format(java.util.Locale.US, n.toFloat() * 3.6f)
            Format.RAD_TO_DEG -> "%.1f° (%s)".format(java.util.Locale.US, Math.toDegrees(n.toDouble()), if (n.toFloat() >= 0) "left" else "right")
            Format.GEAR -> when (n.toInt()) {
                0x00200230 -> "P"; 0x00200240 -> "R"; 0x00200210 -> "N"; 0x00200220 -> "D"
                else -> "unknown 0x${Integer.toHexString(n.toInt())}"
            }
            Format.INDICATOR -> when (n.toInt()) { 0 -> "off"; 1 -> "LEFT"; 2 -> "RIGHT"; 3 -> "HAZARD"; else -> "raw ${n.toInt()}" }
            Format.DAY_NIGHT -> when (n.toInt()) { 0x00201001 -> "day"; 0x00201002 -> "night"; else -> "0x${Integer.toHexString(n.toInt())}" }
        }
    }
}
