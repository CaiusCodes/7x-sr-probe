package au.local.zeekr.srprobe.ui

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import au.local.zeekr.srprobe.ecarx.CaptureSession
import au.local.zeekr.srprobe.ecarx.EcarxAvailability
import au.local.zeekr.srprobe.ecarx.EcarxReflection
import au.local.zeekr.srprobe.ecarx.SensorDiscovery
import au.local.zeekr.srprobe.ecarx.VehicleSignalReader
import au.local.zeekr.srprobe.logging.EventRecorder
import au.local.zeekr.srprobe.model.Availability
import au.local.zeekr.srprobe.model.DexScanRecord
import au.local.zeekr.srprobe.model.DiscoveredApi
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.model.VehicleSignal
import au.local.zeekr.srprobe.platform.AndroidEnvironment
import au.local.zeekr.srprobe.platform.DexScanner
import au.local.zeekr.srprobe.platform.PackageDiscovery
import au.local.zeekr.srprobe.platform.ServiceDiscovery
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.util.concurrent.Executors

/**
 * Holds probe state for the process and runs every step on one background thread, in order.
 * (No AndroidX: a plain process-wide object, owned by ProbeApplication.)
 */
class DiagnosticsViewModel(private val app: Context) {

    val recorder = EventRecorder(app)
    val ecarx = EcarxAvailability()
    val reader = VehicleSignalReader(ecarx)
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "srprobe-worker") }
    private val main = Handler(Looper.getMainLooper())

    // ---- state (read by UI and exporter)
    @Volatile var busy: String? = null; private set
    @Volatile var environment: List<AndroidEnvironment.Section> = emptyList(); private set
    @Volatile var packages: PackageDiscovery.Result? = null; private set
    @Volatile var services: ServiceDiscovery.Result? = null; private set
    @Volatile var signals: List<VehicleSignal> = emptyList(); private set
    @Volatile var apis: List<DiscoveredApi> = emptyList(); private set
    @Volatile var dexScans: List<DexScanRecord> = emptyList(); private set
    @Volatile var namedConstants: List<SensorDiscovery.NamedConstant> = emptyList(); private set
    @Volatile var namedReads: List<SensorDiscovery.NamedRead> = emptyList(); private set
    @Volatile var capture: CaptureSession? = null; private set
    @Volatile var discoveryRunAt: String? = null; private set
    @Volatile var discoveryMs: Long = 0; private set
    @Volatile var parkedAtDiscovery: Boolean? = null; private set
    val errors = java.util.Collections.synchronizedList(ArrayList<String>())

    /** Opt-in: query AIDL interface names of relevant binder services. Off by default. */
    @Volatile var queryBinderDescriptors = false

    var onChange: (() -> Unit)? = null
    private fun changed() = main.post { onChange?.invoke() }

    private fun step(name: String, block: () -> Unit) {
        busy = name
        changed()
        recorder.log("▶ $name")
        val t0 = SystemClock.elapsedRealtime()
        try {
            block()
            recorder.log("✓ $name (${SystemClock.elapsedRealtime() - t0} ms)")
        } catch (t: Throwable) {
            val msg = "$name failed: ${ReadOnlyGuard.describe(t)}"
            errors += msg
            recorder.log("✗ $msg")
        }
        changed()
    }

    fun runSafeDiscovery() = worker.execute {
        val start = SystemClock.elapsedRealtime()
        discoveryRunAt = recorder.now()
        step("Environment") { environment = AndroidEnvironment.collect(app) }
        step("Packages") {
            packages = PackageDiscovery.run(app).also { it.error?.let { e -> errors += "Packages: $e" } }
        }
        step("Binder services${if (queryBinderDescriptors) " (+interface names)" else ""}") {
            services = ServiceDiscovery.run(queryBinderDescriptors)
        }
        val bootScans = ArrayList<DexScanRecord>()
        step("Scan vendor framework jars (names only)") {
            for (jar in vendorJars()) bootScans += DexScanner.scan("framework jar", jar)
            dexScans = bootScans.toList()
        }
        step("ECARX connect") {
            val st = ecarx.connect(app)
            recorder.log("ECARX: ${st.detail}")
            if (st.car != Availability.AVAILABLE) errors += "ECARX: ${st.detail}"
        }
        step("Known vehicle signals") {
            signals = reader.readAllKnown()
            parkedAtDiscovery = reader.isParked()
        }
        step("Reflect vendor classes (inspection only)") {
            val seeds = LinkedHashSet<String>()
            seeds += ReadOnlyGuard.ECARX_CAR_CLASS
            // Every class of the ECARX adapt-API jar (where its constants live), then other relevant vendor names.
            bootScans.forEach { s -> seeds += s.vendorClassNames.filter { it.startsWith("com.ecarx.xui.adaptapi") } }
            bootScans.forEach { s -> seeds += s.matchingClasses.filter { Terms.isVendor(it) } }
            val runtime = listOfNotNull(ecarx.car, ecarx.function, ecarx.sensor, ecarx.carInfo)
            apis = EcarxReflection(javaClass.classLoader!!).inspectAll(seeds, runtime)
            namedConstants = SensorDiscovery.catalogue(apis)
        }
        step("Scan relevant system APKs (names only)") {
            val pkgs = packages?.relevant.orEmpty().filter { it.system && it.sourceDir != null }
                .sortedByDescending { p -> p.matchedTerms.count { it in Terms.STRONG } }
                .take(MAX_APKS)
            val out = ArrayList(bootScans)
            for (p in pkgs) {
                busy = "Scanning ${p.packageName}"
                changed()
                out += DexScanner.scan(p.packageName, p.sourceDir!!)
                dexScans = out.toList()
            }
        }
        discoveryMs = SystemClock.elapsedRealtime() - start
        busy = null
        recorder.log("Safe discovery finished in ${discoveryMs / 1000} s. Export the report next.")
        changed()
    }

    fun refreshSignals() = worker.execute {
        step("Read known signals") {
            if (ecarx.car == null) ecarx.connect(app)
            signals = reader.readAllKnown()
        }
        busy = null; changed()
    }

    /** Returns null when capture may start, or the reason it may not. */
    fun startCapture(confirmedParkedByUser: Boolean): String? {
        if (ecarx.car == null) return "Run Safe Discovery first (ECARX not connected)."
        val parked = reader.isParked()
        if (parked == false) return "Gear does not read P. v0.1 capture must be started while parked."
        if (parked == null && !confirmedParkedByUser) return "GEAR_UNKNOWN"
        val extra = namedReads.filter { it.availability == Availability.AVAILABLE }
            .map { Triple(it.kind, it.constant.value, it.constant.name) }
        capture = CaptureSession(ecarx, reader, recorder, extra).also { it.start() }
        changed()
        return null
    }

    fun stopCapture() {
        capture?.stop()
        changed()
    }

    /** Opt-in step. Returns null when started, or a reason it did not start. */
    fun readNamedConstants(confirmedParkedByUser: Boolean): String? {
        if (namedConstants.isEmpty()) return "No SDK-named ADAS constants catalogued. Run Safe Discovery first."
        val parked = reader.isParked()
        if (parked == false) return "Gear does not read P. This step only runs parked."
        if (parked == null && !confirmedParkedByUser) return "GEAR_UNKNOWN"
        worker.execute {
            step("Opt-in: read SDK-named ADAS ids once (getters only)") {
                namedReads = SensorDiscovery.readCatalogueOnce(reader, namedConstants)
                recorder.log("Named reads: ${namedReads.size}, real values: ${namedReads.count { it.availability == Availability.AVAILABLE }}")
            }
            busy = null; changed()
        }
        return null
    }

    fun runOnWorker(block: () -> Unit) = worker.execute(block)

    /** Framework jars whose file name points at vendor/vehicle code. Listing only; see DexScanner. */
    private fun vendorJars(): List<String> {
        val fromEnv = (System.getenv("BOOTCLASSPATH") ?: "").split(':') + (System.getenv("SYSTEMSERVERCLASSPATH") ?: "").split(':')
        val fromDirs = listOf("/system/framework", "/system_ext/framework", "/product/framework", "/vendor/framework")
            .flatMap { d -> runCatching { java.io.File(d).list()?.map { "$d/$it" } }.getOrNull() ?: emptyList() }
        return (fromEnv + fromDirs).filter { it.endsWith(".jar") }.distinct().filter { p ->
            val n = p.substringAfterLast('/').lowercase()
            listOf("ecarx", "zeekr", "geely", "car", "vehicle", "adas", "vendor", "hmi", "cluster", "scene").any { n.contains(it) }
        }
    }

    companion object {
        const val MAX_APKS = 60
    }
}
