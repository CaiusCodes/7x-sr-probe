package au.local.zeekr.srprobe.model

/**
 * Data model shared by the probe and (later) the 7X Driver View.
 *
 * Everything here is plain data. Nothing in this package touches the vehicle.
 */

/** Outcome of trying to read one thing. Shown verbatim in the UI and report. */
enum class Availability {
    AVAILABLE,
    /** The API answered, but with a placeholder (255/254/253/-1/-65535 or a near-zero float). */
    UNAVAILABLE,
    PERMISSION_DENIED,
    API_NOT_PRESENT,
    ERROR,
    NOT_RUN
}

/** How a known signal is read through the ECARX adapt API. */
enum class ReadKind {
    /** ICarFunction.getFunctionValue(id) */
    FUNCTION,
    /** ICarFunction.getFunctionValue(id, zone) */
    FUNCTION_ZONE,
    /** ISensor.getSensorEvent(type): enumerated value */
    SENSOR_EVENT,
    /** ISensor.getSensorLatestValue(type): float */
    SENSOR_VALUE,
    /** ICarInfo.getCarInfoInt(id) */
    CAR_INFO_INT
}

/** How much we trust the meaning of a signal id. Nothing is "confirmed on the Australian 7X" yet. */
enum class SignalTrust {
    /** Observed consistently on a 7X by the public zeekr-shortcut-car / lab project (market unknown). */
    OBSERVED_ELSEWHERE,
    /** Readable elsewhere but meaning, unit or range not settled. */
    UNVERIFIED
}

data class VehicleSignal(
    val key: String,
    val label: String,
    val kind: ReadKind,
    val id: Int,
    val zone: Int,
    val availability: Availability,
    val rawValue: String?,
    val decodedValue: String?,
    val note: String?,
    val readAtElapsedNs: Long
)

/** How a discovered method was classified. Only ALLOWLISTED methods are ever invoked. */
enum class MethodClass {
    /** In ReadOnlyGuard's allowlist and invoked by this probe. */
    ALLOWLISTED,
    /** Name looks like a read (get/is/has/query) but semantics are not proven. Listed, never invoked. */
    READ_NAME_UNVERIFIED,
    /** Listener/callback registration. Listed, never invoked unless allowlisted. */
    LISTENER_UNVERIFIED,
    /** Name suggests mutation or an action (set/send/start/...). Never invoked. */
    MUTATOR_NEVER_CALLED,
    /** Anything else. Never invoked. */
    OTHER_NOT_CALLED
}

data class MethodInfo(
    val name: String,
    val parameterTypes: List<String>,
    val returnType: String,
    val isStatic: Boolean,
    val classification: MethodClass,
    val matchedTerms: List<String>
)

data class FieldInfo(
    val name: String,
    val type: String,
    val isStatic: Boolean,
    val isFinal: Boolean,
    val isEnumConstant: Boolean,
    /** Only filled for constants we were allowed to read (see EcarxReflection); otherwise null. */
    val constantValue: String?,
    val matchedTerms: List<String>
)

data class DiscoveredApi(
    val className: String,
    val kind: String,
    val source: String,
    val superclass: String?,
    val interfaces: List<String>,
    val methods: List<MethodInfo>,
    val fields: List<FieldInfo>,
    val nestedClasses: List<String>,
    val matchedTerms: List<String>,
    val error: String?
) {
    val isListenerLike: Boolean
        get() = kind == "interface" && methods.isNotEmpty() && methods.all { it.name.startsWith("on") }
}

/** One timestamped observation from the capture logger. Matches the JSONL schema in the brief. */
data class ProbeEvent(
    val monotonicNs: Long,
    val timestamp: String,
    val source: String,
    val api: String,
    val eventId: String?,
    val rawType: String?,
    val rawValue: String?,
    val decodedValue: String?
)

/** A visible package that matched a relevance term. */
data class PackageRecord(
    val packageName: String,
    val label: String?,
    val versionName: String?,
    val versionCode: Long,
    val enabled: Boolean,
    val system: Boolean,
    val sourceDir: String?,
    val matchedTerms: List<String>,
    val activities: List<ComponentRecord>,
    val services: List<ComponentRecord>,
    val receivers: List<ComponentRecord>,
    val providers: List<ComponentRecord>,
    val requestedPermissions: List<String>,
    val error: String?
)

data class ComponentRecord(
    val name: String,
    val exported: Boolean,
    val enabled: Boolean,
    val permission: String?,
    /** Content provider authority, when this is a provider. Never queried. */
    val authority: String? = null
)

data class ServiceRecord(
    val name: String,
    val descriptor: String?,
    val matchedTerms: List<String>,
    val note: String?
)

/** What a scanned dex/APK/jar contained that matched relevance terms. Names only; no code is loaded. */
data class DexScanRecord(
    val source: String,
    val path: String,
    val dexFiles: Int,
    val totalClasses: Int,
    val matchingClasses: List<String>,
    val matchingStrings: List<String>,
    val nativeLibs: List<String>,
    val matchingAssets: List<String>,
    val note: String?,
    /** Every class in a vehicle-vendor namespace (capped), used to seed reflection of the ECARX jar. */
    val vendorClassNames: List<String> = emptyList(),
    /** v0.2: class names scored by Terms.perceptionScore, highest first, as "score name". */
    val perceptionClasses: List<String> = emptyList(),
    /** v0.2: vendor AIDL interface names, intent actions and content authorities found as dex strings. */
    val endpointStrings: List<String> = emptyList(),
    /** v0.2: vendor-namespace strings from the APK's binary AndroidManifest.xml (permissions, actions, components). */
    val manifestStrings: List<String> = emptyList()
)

// ---------------------------------------------------------------------------------------------
// Future visualizer model (NOT used by v0.1 logic). Kept here so provenance and staleness are part
// of the design from day one: a later Driver View must never render an object without knowing
// where it came from, how old it is and how confident the source was.
// ---------------------------------------------------------------------------------------------

enum class DetectionSource {
    FACTORY_PERCEPTION,
    FACTORY_CLUSTER_SCENE,
    FACTORY_BSD,
    FACTORY_ACC,
    CAMERA_AI,
    FUSED,
    UNKNOWN
}

enum class ObjectType { CAR, TRUCK, BUS, MOTORCYCLE, CYCLIST, PEDESTRIAN, CONE, BARRIER, UNKNOWN }

data class SceneObject(
    val trackId: String?,
    val type: ObjectType,
    /** Units and axes are unknown until confirmed from factory data. Raw values are kept alongside. */
    val x: Float?,
    val y: Float?,
    val heading: Float?,
    val relativeVelocity: Float?,
    val confidence: Float?,
    val source: DetectionSource,
    val observedAtNanos: Long,
    val lastUpdatedAtNanos: Long,
    val rawFields: Map<String, String> = emptyMap()
) {
    fun ageNanos(nowNanos: Long): Long = nowNanos - lastUpdatedAtNanos
}
