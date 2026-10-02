package au.local.zeekr.srprobe.safety

import au.local.zeekr.srprobe.model.MethodClass
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.UndeclaredThrowableException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * The single gate every vehicle-platform reflective invocation must pass through.
 *
 * READ_ONLY_AUDIT.md documents each entry in [ALLOWED]. To add an entry you must first add it to the
 * audit with evidence that it is read-only. Any method that is not listed here, or whose name starts with
 * a mutating verb, throws [ReadOnlyViolation] instead of being invoked.
 *
 * Android framework reads (PackageManager, ServiceManager.listServices, SystemProperties.get) go through
 * [invokeFramework], which has its own allowlist and is audited separately.
 */
object ReadOnlyGuard {

    /** The ECARX adapt-API class whose static create(Context) is the only factory we call. */
    const val ECARX_CAR_CLASS = "com.ecarx.xui.adaptapi.car.Car"

    /**
     * Allowed vehicle-platform methods, keyed by name with the exact parameter shape we accept.
     * "I" = int, "Ctx" = android.content.Context, "I[]" = int[], "L" = a listener interface.
     */
    private val ALLOWED: Map<String, Set<String>> = mapOf(
        // Factory and manager getters (no arguments, return manager objects).
        "create" to setOf("Ctx"),
        "getICarFunction" to setOf(""),
        "getSensorManager" to setOf(""),
        "getCarInfoManager" to setOf(""),
        // Value getters.
        "getFunctionValue" to setOf("I", "I,I"),
        "getSensorEvent" to setOf("I"),
        "getSensorLatestValue" to setOf("I"),
        "getCarInfoInt" to setOf("I"),
        // Change subscriptions (capture mode only). Deliver values to us; do not change vehicle state.
        "registerFunctionValueWatcher" to setOf("I[],L", "I,L"),
        "unregisterFunctionValueWatcher" to setOf("L", "I[],L", "I,L"),
        "registerListener" to setOf("L,I")
    )

    /** Belt and braces: even an allowlisted name is refused if it starts like a mutator. */
    private val MUTATING_PREFIXES = listOf(
        "set", "put", "write", "send", "start", "stop", "open", "close", "enable", "disable", "reset",
        "request", "trigger", "execute", "perform", "apply", "clear", "delete", "remove", "update", "inject",
        "flash", "install", "launch", "activate", "deactivate", "control", "do", "commit", "notify", "sync",
        "init", "bind", "connect", "lock", "unlock", "switch", "toggle", "change", "modify", "save", "restore",
        "calibrate", "upgrade", "reboot", "shutdown", "power", "wake", "sleep", "play", "pause", "press", "click",
        "invoke", "call", "transact", "exec", "run", "post", "dispatch", "publish", "push", "load", "unload"
    )

    private val READ_PREFIXES = listOf("get", "is", "has", "query", "can", "contains", "supports")
    private val LISTENER_PREFIXES = listOf("register", "unregister", "add", "remove", "watch", "unwatch", "subscribe", "unsubscribe")

    private val ledger = ConcurrentHashMap<String, AtomicLong>()

    class ReadOnlyViolation(message: String) : SecurityException(message)

    fun shapeOf(m: Method): String = m.parameterTypes.joinToString(",") { p ->
        when {
            p == Int::class.javaPrimitiveType -> "I"
            p == IntArray::class.java -> "I[]"
            p.name == "android.content.Context" -> "Ctx"
            p.isInterface -> "L"
            else -> p.name
        }
    }

    fun isAllowed(m: Method): Boolean {
        val shapes = ALLOWED[m.name] ?: return false
        if (shapeOf(m) !in shapes) return false
        if (m.name == "create" && m.declaringClass.name != ECARX_CAR_CLASS) return false
        // The allowlist contains register*/unregister* which are not mutators; everything else must
        // also clear the mutating-prefix check.
        if (!m.name.startsWith("register") && !m.name.startsWith("unregister") && m.name != "create" &&
            MUTATING_PREFIXES.any { m.name.startsWith(it) }) return false
        return true
    }

    /** Invoke an allowlisted vehicle-platform method, or throw without invoking it. */
    fun invoke(m: Method, target: Any?, vararg args: Any?): Any? {
        if (!isAllowed(m)) {
            throw ReadOnlyViolation("Refused (not in read-only allowlist): ${m.declaringClass.name}.${m.name}(${shapeOf(m)})")
        }
        count("vehicle:${m.declaringClass.name}.${m.name}(${shapeOf(m)})")
        return unwrap { m.invoke(target, *args) }
    }

    /**
     * v0.4 SR-feed subscription (audited separately in READ_ONLY_AUDIT.md section F).
     *
     * This is the ONLY path that touches the Zeekr perception SDK (`com.zeekr.*`). Exactly two kinds of
     * call are permitted, and only on Zeekr-namespace classes:
     *   1. zero-argument getters (`get`, `getNavi`, `getXxx`, `isXxx`) — pure reads that return the API
     *      handle or a received data bean's field; they take nothing and change nothing;
     *   2. the observer (un)subscribe pair below, each taking a single callback interface — they ask the
     *      service to DELIVER perception updates to us; they send no vehicle command and carry no payload.
     * Every other SDK method — all `send*`, `set*`, `init*`, `recoverRegistered`, `call`/`asyncCall`,
     * `onTransact` and the rest — is refused here and listed in the report, never invoked.
     */
    private val SR_OBSERVER_METHODS = setOf("registerSRObjectsObserver", "unregisterSRObjectsObserver")
    private const val SR_NAMESPACE = "com.zeekr."

    fun isSrAllowed(m: Method): Boolean {
        if (!m.declaringClass.name.startsWith(SR_NAMESPACE)) return false
        val args = m.parameterTypes
        // (1) zero-arg reads.
        if (args.isEmpty() && (m.name.startsWith("get") || m.name.startsWith("is"))) {
            return !MUTATING_PREFIXES.any { m.name.startsWith(it) }
        }
        // (2) the exact observer subscribe/unsubscribe, with a single callback-interface argument.
        return m.name in SR_OBSERVER_METHODS && args.size == 1 && args[0].isInterface
    }

    /** Invoke an SR-feed method that passed [isSrAllowed], or throw without invoking it. */
    fun invokeSr(m: Method, target: Any?, vararg args: Any?): Any? {
        if (!isSrAllowed(m)) {
            throw ReadOnlyViolation("Refused (not on SR read-only allowlist): ${m.declaringClass.name}.${m.name}(${shapeOf(m)})")
        }
        count("sr:${m.declaringClass.name}.${m.name}(${shapeOf(m)})")
        return unwrap { m.invoke(target, *args) }
    }

    /**
     * v0.5: content-provider reads (READ_ONLY_AUDIT.md section G). Only ContentResolver.query and getType,
     * only on these authorities (exported by ZeekrVehicleService). insert/update/delete/call/openFile are
     * never used.
     */
    val PROVIDER_AUTHORITIES = setOf("com.zeekr.vehicle.data")

    fun isProviderAllowed(scheme: String?, authority: String?): Boolean =
        scheme == "content" && authority in PROVIDER_AUTHORITIES

    fun queryProvider(resolver: android.content.ContentResolver, uri: android.net.Uri): android.database.Cursor? {
        if (!isProviderAllowed(uri.scheme, uri.authority)) {
            throw ReadOnlyViolation("Refused provider read outside the allowlist: $uri")
        }
        count("provider:query(${uri.authority})")
        return resolver.query(uri, null, null, null, null)
    }

    fun providerType(resolver: android.content.ContentResolver, uri: android.net.Uri): String? {
        if (!isProviderAllowed(uri.scheme, uri.authority)) {
            throw ReadOnlyViolation("Refused provider read outside the allowlist: $uri")
        }
        count("provider:getType(${uri.authority})")
        return resolver.getType(uri)
    }

    /** Android framework methods the probe may call by reflection. All are documented reads. */
    private val FRAMEWORK_ALLOWED = setOf(
        "android.os.ServiceManager.listServices()",
        "android.os.ServiceManager.checkService(java.lang.String)",
        "android.os.SystemProperties.get(java.lang.String)"
    )

    fun invokeFramework(m: Method, target: Any?, vararg args: Any?): Any? {
        val sig = "${m.declaringClass.name}.${m.name}(${m.parameterTypes.joinToString(",") { it.name }})"
        if (sig !in FRAMEWORK_ALLOWED) throw ReadOnlyViolation("Refused framework call: $sig")
        count("framework:$sig")
        return unwrap { m.invoke(target, *args) }
    }

    /** Record a non-reflective call (e.g. IBinder.getInterfaceDescriptor) so the ledger is complete. */
    fun count(signature: String) {
        ledger.getOrPut(signature) { AtomicLong() }.incrementAndGet()
    }

    fun ledgerSnapshot(): Map<String, Long> = ledger.entries.associate { it.key to it.value.get() }.toSortedMap()

    fun classify(name: String, allowlisted: Boolean): MethodClass = when {
        allowlisted -> MethodClass.ALLOWLISTED
        LISTENER_PREFIXES.any { name.startsWith(it) } && name.contains("Listener", true) ||
            name.startsWith("register") || name.startsWith("unregister") -> MethodClass.LISTENER_UNVERIFIED
        READ_PREFIXES.any { startsWithWord(name, it) } -> MethodClass.READ_NAME_UNVERIFIED
        MUTATING_PREFIXES.any { startsWithWord(name, it) } -> MethodClass.MUTATOR_NEVER_CALLED
        else -> MethodClass.OTHER_NOT_CALLED
    }

    private fun startsWithWord(name: String, prefix: String): Boolean =
        name.startsWith(prefix) && (name.length == prefix.length || !name[prefix.length].isLowerCase())

    private inline fun unwrap(block: () -> Any?): Any? = try {
        block()
    } catch (e: InvocationTargetException) {
        throw e.targetException ?: e
    } catch (e: UndeclaredThrowableException) {
        throw e.undeclaredThrowable ?: e
    }

    fun describe(t: Throwable): String {
        var e: Throwable = t
        while ((e is InvocationTargetException || e is UndeclaredThrowableException) && e.cause != null) e = e.cause!!
        return e.javaClass.simpleName + (e.message?.let { ": " + it.take(300) } ?: "")
    }
}
