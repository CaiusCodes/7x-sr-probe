package au.local.zeekr.srprobe.ui

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import au.local.zeekr.srprobe.ecarx.CaptureSession
import au.local.zeekr.srprobe.ecarx.EcarxAvailability
import au.local.zeekr.srprobe.ecarx.EcarxReflection
import au.local.zeekr.srprobe.ecarx.SensorDiscovery
import au.local.zeekr.srprobe.ecarx.SrFeed
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
import au.local.zeekr.srprobe.platform.SystemFiles
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
    @Volatile var appFolders: Int = 0; private set
    @Volatile var appScanNote: String? = null; private set
    @Volatile var configNames: List<String> = emptyList(); private set
    @Volatile var srInspect: List<au.local.zeekr.srprobe.platform.DexInspector.Result> = emptyList(); private set
    @Volatile var srFeed: SrFeed? = null; private set
    @Volatile var providerPaths: List<au.local.zeekr.srprobe.platform.ProviderPaths.Found> = emptyList(); private set
    @Volatile var providerResults: List<au.local.zeekr.srprobe.platform.ProviderProbe.UriResult> = emptyList(); private set
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
        val out = ArrayList(bootScans)
        step("Scan relevant system APKs (names only)") {
            val pkgs = packages?.relevant.orEmpty().filter { it.system && it.sourceDir != null }
                .sortedByDescending { p -> p.matchedTerms.count { it in Terms.STRONG } }
                .take(MAX_APKS)
            for (p in pkgs) {
                busy = "Scanning ${p.packageName}"
                changed()
                out += DexScanner.scan(p.packageName, p.sourceDir!!, light = true)
                dexScans = out.toList()
            }
        }
        step("Scan system app folders (names only)") {
            val folders = SystemFiles.appFolders().sortedByDescending { SystemFiles.priority(it) }
            appFolders = folders.size
            val done = out.map { it.path }.toHashSet()
            val t0 = SystemClock.elapsedRealtime()
            var scanned = 0
            var stopped: String? = null
            for ((i, f) in folders.withIndex()) {
                if (scanned >= MAX_FOLDER_APKS) { stopped = "stopped at the $MAX_FOLDER_APKS-APK limit"; break }
                if (SystemClock.elapsedRealtime() - t0 > FOLDER_BUDGET_MS) { stopped = "stopped at the ${FOLDER_BUDGET_MS / 60000}-minute budget"; break }
                val name = f.folder.substringAfterLast('/')
                busy = "Scanning app ${i + 1}/${folders.size}: $name"
                if (i % 5 == 0) changed()
                var hadDex = false
                for (apk in f.apks) {
                    if (apk in done) continue
                    val r = DexScanner.scan(name, apk, light = true)
                    out += r
                    hadDex = hadDex || r.dexFiles > 0
                    scanned++
                }
                if (!hadDex) f.vdex.firstOrNull()?.let { out += DexScanner.scanContainer("$name (vdex)", it) }
                if (i % 10 == 0) dexScans = out.toList()
            }
            dexScans = out.toList()
            appScanNote = "${folders.size} app folders found; $scanned APKs scanned in ${(SystemClock.elapsedRealtime() - t0) / 1000} s" +
                (stopped?.let { "; $it" } ?: "") + "; dirs: " + SystemFiles.dirNotes.entries.joinToString { "${it.key} ${it.value}" }
            recorder.log(appScanNote!!)
        }
        step("List config file names (names only)") { configNames = SystemFiles.configNames() }
        step("Inspect SR-object apps (names only)") {
            val hits = dexScans.filter { d ->
                d.source.substringBefore(" (vdex)") in SR_APPS || d.path.contains("ts-carplay-adapter") ||
                    d.perceptionClasses.any { SR_HINT.containsMatchIn(it) } || d.endpointStrings.any { SR_HINT.containsMatchIn(it) }
            }.distinctBy { it.path }.take(12)
            val res = ArrayList<au.local.zeekr.srprobe.platform.DexInspector.Result>()
            for (d in hits) {
                busy = "Inspecting ${d.source}"
                changed()
                res += au.local.zeekr.srprobe.platform.DexInspector.inspect(d.source, d.path)
                srInspect = res.toList()
            }
            recorder.log("SR inspection: ${res.size} sources, ${res.sumOf { it.classes.size }} classes")
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

    /** v0.4 opt-in: subscribe to the SR-object feed. Parked only. Returns null when started, else a reason. */
    fun startSrFeed(confirmedParkedByUser: Boolean): String? {
        val parked = reader.isParked()
        if (parked == false) return "Gear does not read P. The SR feed only runs while parked."
        if (parked == null && !confirmedParkedByUser) return "GEAR_UNKNOWN"
        val jar = dexScans.map { it.path }.firstOrNull { it.contains("ts-carplay-adapter") }
            ?: dexScans.firstOrNull { it.vendorClassNames.any { c -> c.startsWith("com.zeekr.sdk.adcu") } }?.path
        val feed = SrFeed(app)
        srFeed = feed
        changed()
        worker.execute {
            step("Opt-in: subscribe to SR-object feed (parked, read-only)") {
                recorder.log("SR feed: " + feed.start(jar))
            }
            busy = null; changed()
        }
        return null
    }

    /** v0.5 opt-in: read-only query of com.zeekr.vehicle.data. Parked only. */
    fun queryProvider(confirmedParkedByUser: Boolean, done: () -> Unit): String? {
        val parked = reader.isParked()
        if (parked == false) return "Gear does not read P. This step only runs parked."
        if (parked == null && !confirmedParkedByUser) return "GEAR_UNKNOWN"
        val auth = "com.zeekr.vehicle.data"
        val scanUris = dexScans.flatMap { it.endpointStrings + it.matchingStrings }.filter { it.startsWith("content://$auth") }
        val extra = dexScans.filter { d -> (d.manifestStrings + d.endpointStrings).any { it.contains(auth) } }.map { it.path }
        worker.execute {
            step("Find provider paths in ZeekrVehicleService (names only)") {
                providerPaths = au.local.zeekr.srprobe.platform.ProviderPaths.inspect("ZeekrVehicleService", extra, auth)
                recorder.log("Provider paths: ${providerPaths.sumOf { it.strings.size }} strings in ${providerPaths.size} files")
            }
            step("Opt-in: query vehicle data provider (read-only)") {
                val vendorUris = (scanUris + au.local.zeekr.srprobe.platform.ProviderPaths.candidatePaths(providerPaths, auth)).distinct()
                providerResults = au.local.zeekr.srprobe.platform.ProviderProbe.run(app, vendorUris)
                recorder.log("Provider: ${providerResults.size} URIs, ${providerResults.count { it.error == null }} answered")
            }
            busy = null; changed()
            main.post(done)
        }
        return null
    }

    fun stopSrFeed() = worker.execute {
        srFeed?.stop()
        recorder.log("SR feed stopped")
        changed()
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
        const val MAX_FOLDER_APKS = 400
        val SR_APPS = setOf("ZeekrVehicleService", "ZeekrCarLauncherScene3D", "CarControlMultiDisplay", "XCLauncher3", "ZeekrCarService")
        val SR_HINT = Regex("SRObject|autopilot\\.sr|PercepFusion|soa\\.adcu|sdk\\.adcu")
        const val FOLDER_BUDGET_MS = 8 * 60_000L
    }
}
