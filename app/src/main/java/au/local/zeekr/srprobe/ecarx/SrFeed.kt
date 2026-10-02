package au.local.zeekr.srprobe.ecarx

import android.content.Context
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import dalvik.system.DexClassLoader
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.concurrent.atomic.AtomicInteger

/**
 * v0.4: subscribes to the car's SR-object (surrounding-vehicle) feed, parked and read-only, using the
 * same path the factory 3D launcher uses: AdcuAPI.get().getNavi().registerSRObjectsObserver(observer).
 *
 * Every call into the Zeekr SDK goes through ReadOnlyGuard.invokeSr, which permits only zero-argument
 * getters and the observer subscribe/unsubscribe pair (READ_ONLY_AUDIT.md section F). The observer is a
 * java.lang.reflect.Proxy: it can only receive callbacks, never send anything. The received objects are
 * read with zero-argument getters and never stored beyond this process. If any step needs a method that
 * is not on the allowlist, the guard refuses it and we report where it stopped — nothing unlisted is run.
 */
class SrFeed(private val context: Context) {

    data class Pos(val fields: Map<String, String>)
    data class Obj(val fields: Map<String, String>)
    data class Snapshot(val carPos: Pos?, val objects: List<Obj>, val raw: String?)

    @Volatile var steps: List<String> = emptyList(); private set
    @Volatile var outcome: String = "not started"; private set
    @Volatile var last: Snapshot? = null; private set
    val updates = AtomicInteger(0)

    private val log = ArrayList<String>()
    private var loader: ClassLoader? = null
    private var navi: Any? = null
    private var observer: Any? = null
    private var observerIface: Class<*>? = null

    private fun step(s: String) { synchronized(log) { log.add(s); steps = log.toList() } }

    /** Zero-arg getter through the guard; returns null (not throws) so callers can branch. */
    private fun get(target: Any, name: String): Any? = runCatching {
        ReadOnlyGuard.invokeSr(target.javaClass.getMethod(name), target)
    }.getOrNull()

    /** Read every zero-arg get/is accessor on an object (one level deep for nested beans), via the guard. */
    private fun readBean(o: Any?, depth: Int = 1): Map<String, String> {
        if (o == null) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (m in o.javaClass.methods) {
            if (m.parameterTypes.isNotEmpty()) continue
            if (!(m.name.startsWith("get") || m.name.startsWith("is"))) continue
            if (m.name == "getClass") continue
            if (!ReadOnlyGuard.isSrAllowed(m)) continue
            val v = runCatching { ReadOnlyGuard.invokeSr(m, o) }.getOrNull() ?: continue
            val label = m.name.removePrefix("get").removePrefix("is").replaceFirstChar { it.lowercase() }
            out[label] = when {
                v is Number || v is Boolean || v is String -> v.toString()
                depth > 0 && v.javaClass.name.startsWith("com.zeekr") -> "{" + readBean(v, depth - 1).entries.joinToString(", ") { "${it.key}=${it.value}" } + "}"
                else -> v.javaClass.simpleName
            }
        }
        return out
    }

    /**
     * Connects and subscribes. Returns the outcome string. Call stop() when leaving the screen.
     * jarPath is the framework jar that holds com.zeekr.sdk.adcu.AdcuAPI (from the discovery scan);
     * may be null, in which case we only try the app's own class loader.
     */
    fun start(jarPath: String?): String {
        try {
            val apiCls = resolve("com.zeekr.sdk.adcu.AdcuAPI", jarPath)
                ?: return fail("Could not load the Zeekr ADCU SDK (com.zeekr.sdk.adcu.AdcuAPI). " +
                    "On this head unit it lives in a framework jar an ordinary app cannot load.")
            step("Loaded ${apiCls.name} via ${if (loader is DexClassLoader) "DexClassLoader($jarPath)" else "app class loader"}")

            val getM = apiCls.getMethod("get")
            if (!ReadOnlyGuard.isSrAllowed(getM)) return fail("AdcuAPI.get() is not on the allowlist")
            val api = ReadOnlyGuard.invokeSr(getM, null)
                ?: return fail("AdcuAPI.get() returned null (SDK not initialised for this app)")
            step("AdcuAPI.get() -> ${api.javaClass.name}")

            val navi = get(api, "getNavi") ?: return fail("getNavi() returned null or is unavailable")
            this.navi = navi
            step("getNavi() -> ${navi.javaClass.name}")

            val iface = resolve("com.zeekr.sdk.adcu.observer.ISRObjectsObserver", jarPath)
                ?: return fail("Observer interface ISRObjectsObserver not loadable")
            observerIface = iface
            observer = Proxy.newProxyInstance(iface.classLoader, arrayOf(iface), Handler())
            step("Built observer proxy for ${iface.name}")

            val reg = navi.javaClass.methods.firstOrNull { it.name == "registerSRObjectsObserver" && it.parameterTypes.size == 1 }
                ?: return fail("registerSRObjectsObserver(observer) not found on ${navi.javaClass.name}")
            if (!ReadOnlyGuard.isSrAllowed(reg)) return fail("registerSRObjectsObserver is not on the allowlist")
            val result = ReadOnlyGuard.invokeSr(reg, navi, observer)
            step("registerSRObjectsObserver(observer) returned $result")
            outcome = "Subscribed. Waiting for the car to push SR objects. If nothing arrives in ~15 s, the feed " +
                "is not delivered to an App Lab app (even though the call was accepted)."
            return outcome
        } catch (t: Throwable) {
            return fail("Stopped at a guarded step: ${ReadOnlyGuard.describe(t)}")
        }
    }

    fun stop() {
        val navi = navi ?: return
        val obs = observer ?: return
        runCatching {
            val unreg = navi.javaClass.methods.firstOrNull { it.name == "unregisterSRObjectsObserver" && it.parameterTypes.size == 1 }
            if (unreg != null && ReadOnlyGuard.isSrAllowed(unreg)) {
                ReadOnlyGuard.invokeSr(unreg, navi, obs)
                step("unregisterSRObjectsObserver(observer) called")
            }
        }
        observer = null
    }

    private fun fail(msg: String): String { step("STOP: $msg"); outcome = msg; return msg }

    /** Load a class without running its static initialiser; app loader first, then the framework jar. */
    private fun resolve(name: String, jarPath: String?): Class<*>? {
        try {
            return Class.forName(name, false, javaClass.classLoader).also { loader = it.classLoader }
        } catch (t: Throwable) {
            step("app class loader: ${ReadOnlyGuard.describe(t)}")
        }
        if (jarPath == null) { step("no framework jar holding $name was found by discovery"); return null }
        val f = java.io.File(jarPath)
        step("jar $jarPath: exists=${f.exists()} readable=${f.canRead()} size=${f.length()}")
        try {
            val dl = loader as? DexClassLoader
                ?: DexClassLoader(jarPath, context.codeCacheDir.absolutePath, null, javaClass.classLoader).also { loader = it }
            return Class.forName(name, false, dl)
        } catch (t: Throwable) {
            var e: Throwable? = t
            val chain = ArrayList<String>()
            while (e != null && chain.size < 4) { chain += ReadOnlyGuard.describe(e); e = e.cause?.takeIf { it !== e } }
            step("DexClassLoader: " + chain.joinToString(" <- "))
        }
        return null
    }

    private inner class Handler : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any?>?): Any? {
            when (method.name) {
                "equals" -> return proxy === args?.getOrNull(0)
                "hashCode" -> return System.identityHashCode(proxy)
                "toString" -> return "SrObserverProxy"
            }
            // Any callback carrying the SR data. Read it; never call back into the service.
            val payload = args?.firstOrNull { it != null && it.javaClass.name.startsWith("com.zeekr") }
            if (payload != null) runCatching {
                updates.incrementAndGet()
                val carPos = get(payload, "getCarPos")?.let { Pos(readBean(it)) }
                val objsRaw = get(payload, "getObjects") as? List<*>
                val objs = objsRaw.orEmpty().filterNotNull().take(64).map { Obj(readBean(it)) }
                last = Snapshot(carPos, objs, if (objs.isEmpty()) readBean(payload).toString() else null)
                step("onValueChange: ${objs.size} objects" + (carPos?.let { ", car ${it.fields}" } ?: ""))
            }
            return when (method.returnType) {
                Boolean::class.javaPrimitiveType -> true
                Int::class.javaPrimitiveType, Long::class.javaPrimitiveType -> 0
                else -> null
            }
        }
    }
}
