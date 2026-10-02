// JVM smoke test: runs the probe's ECARX layer against the fake adapt API above and fails if any
// method outside READ_ONLY_AUDIT.md is invoked. Run: tools/jvm-smoke/run.sh
import au.local.zeekr.srprobe.ecarx.*
import au.local.zeekr.srprobe.model.Availability
import au.local.zeekr.srprobe.platform.DexScanner
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import com.ecarx.xui.adaptapi.car.Calls

class FakeContext : android.content.ContextWrapper(null) {
    private val dir = java.nio.file.Files.createTempDirectory("srprobe-test").toFile()
    override fun getApplicationContext(): android.content.Context = this
    override fun getFilesDir(): java.io.File = dir
    override fun getPackageName(): String = "au.local.zeekr.srprobe"
}

fun check(cond: Boolean, msg: String) { if (!cond) { System.err.println("FAIL: $msg"); kotlin.system.exitProcess(1) }; println("ok   $msg") }

fun main(args: Array<String>) {
    val ecarx = EcarxAvailability()
    check(ecarx.classPresent(), "Car class present")
    val st = ecarx.connect(FakeContext())
    check(st.car == Availability.AVAILABLE, "connect: ${st.detail}")
    val reader = VehicleSignalReader(ecarx)
    val signals = reader.readAllKnown()
    check(signals.first { it.key == "GEAR" }.decodedValue == "P", "gear decodes to P")
    check(signals.first { it.key == "INDICATOR_STATUS" }.decodedValue == "LEFT", "indicator decodes LEFT")
    check(signals.first { it.key == "DRIVE_PILOT" }.availability == Availability.UNAVAILABLE, "255 placeholder -> UNAVAILABLE")
    check(reader.isParked() == true, "isParked")

    val apis = EcarxReflection(Thread.currentThread().contextClassLoader).inspectAll(listOf(ReadOnlyGuard.ECARX_CAR_CLASS),
        listOfNotNull(ecarx.car, ecarx.function, ecarx.sensor, ecarx.carInfo))
    println("reflected: " + apis.joinToString { it.className })
    check(apis.any { it.className.endsWith("IPerceptionManager") }, "perception interface discovered by reachability (not invoked)")
    val cat = SensorDiscovery.catalogue(apis)
    println("catalogue: " + cat.joinToString { "${it.name}=${Integer.toHexString(it.value)} ${it.readAs}" })
    check(cat.any { it.name == "SETTING_FUNC_ADAS_ACC_STATUS" }, "ADAS constant catalogued from interface")
    check(apis.first { it.className.endsWith("Car\$Companion") }.fields.all { it.constantValue == null }, "class constants not read (no class init)")
    check(cat.none { it.name == "SETTING_FUNC_SEAT_HEAT" }, "non-ADAS constant not catalogued")
    val reads = SensorDiscovery.readCatalogueOnce(reader, cat)
    check(reads.isNotEmpty(), "opt-in reads use getters: ${reads.map { it.kind }}")

    // The guard must refuse mutators and unverified getters even if someone tries to route them through it.
    val setter = com.ecarx.xui.adaptapi.car.ICarFunction::class.java.getMethod("setFunctionValue", Int::class.java, Int::class.java)
    check(runCatching { ReadOnlyGuard.invoke(setter, ecarx.function, 1, 1) }.isFailure, "guard refuses setFunctionValue")
    val unverified = com.ecarx.xui.adaptapi.car.ICar::class.java.getMethod("getPerceptionManager")
    check(runCatching { ReadOnlyGuard.invoke(unverified, ecarx.car) }.isFailure, "guard refuses unverified getPerceptionManager")

    check(Calls.log.none { it.startsWith("MUTATOR") || it.startsWith("UNVERIFIED") }, "no mutator or unverified method was invoked")

    // v0.4: the SR-feed allowlist permits only zero-arg reads and the observer subscribe/unsubscribe.
    val navi = com.zeekr.sdk.adcu.NaviFake::class.java
    val obs = com.zeekr.sdk.adcu.ISrObsFake::class.java
    check(ReadOnlyGuard.isSrAllowed(navi.getMethod("getNavi")), "SR allowlist: getNavi (zero-arg read) allowed")
    check(ReadOnlyGuard.isSrAllowed(navi.getMethod("getObjectID")), "SR allowlist: bean getter allowed")
    check(ReadOnlyGuard.isSrAllowed(navi.getMethod("registerSRObjectsObserver", obs)), "SR allowlist: registerSRObjectsObserver allowed")
    check(ReadOnlyGuard.isSrAllowed(navi.getMethod("unregisterSRObjectsObserver", obs)), "SR allowlist: unregister allowed")
    check(!ReadOnlyGuard.isSrAllowed(navi.getMethod("sendCityInfo", obs)), "SR allowlist: sendCityInfo refused")
    check(!ReadOnlyGuard.isSrAllowed(navi.getMethod("setThing", Int::class.javaPrimitiveType)), "SR allowlist: setThing refused")
    check(!ReadOnlyGuard.isSrAllowed(navi.getMethod("init", Array<String>::class.java)), "SR allowlist: init refused")
    check(!ReadOnlyGuard.isSrAllowed(String::class.java.getMethod("length")), "SR allowlist: non-zeekr class refused")
    check(runCatching { ReadOnlyGuard.invokeSr(navi.getMethod("sendCityInfo", obs), com.zeekr.sdk.adcu.NaviFake(), null) }.isFailure, "invokeSr refuses a sender")
    check(ReadOnlyGuard.invokeSr(navi.getMethod("getObjectID"), com.zeekr.sdk.adcu.NaviFake()) == 7L, "invokeSr runs an allowed read")
    val T = au.local.zeekr.srprobe.model.Terms
    check(T.perceptionScore("com.zeekr.adas.ObstacleInfo") >= 2, "perception score: ObstacleInfo listed")
    check(T.perceptionScore("com.example.player.TrackInfo") == 0, "perception score: media TrackInfo ignored")
    check(T.perceptionScore("org.json.JSONObject") == 0, "perception score: JSONObject ignored")
    println("vehicle calls: " + Calls.log.groupingBy { it.substringBefore('(') }.eachCount())
    println("ledger: " + ReadOnlyGuard.ledgerSnapshot())

    if (args.isNotEmpty()) {
        val r = DexScanner.scan("apk", args[0])
        check(r.totalClasses > 100, "dex parser read ${r.totalClasses} classes from the built APK")
        // v0.2: a dex image embedded in a larger file (as in a .vdex) is found and parsed.
        val dex = java.util.zip.ZipFile(args[0]).use { z -> z.getInputStream(z.getEntry("classes.dex")).readBytes() }
        val tmp = java.io.File.createTempFile("probe", ".vdex")
        tmp.writeBytes(ByteArray(333) { 7 } + dex + ByteArray(91))
        val v = DexScanner.scanContainer("vdex", tmp.path)
        check(v.dexFiles == 1 && v.totalClasses == r.totalClasses, "vdex-style container: ${v.dexFiles} dex, ${v.totalClasses} classes")
        val m = java.util.zip.ZipFile(args[0]).use { z -> z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes() }
        check(runCatching { DexScanner.manifestStrings(m) }.isSuccess, "binary manifest string pool parses")
    }
    // Whole pipeline: discovery steps (most fail harmlessly without a real PackageManager) then every export format.
    if (args.isNotEmpty()) {
        // Fake system partition: one app folder holding the built APK, one holding only a vdex.
        val root = java.nio.file.Files.createTempDirectory("sysapp").toFile()
        java.io.File(root, "ZeekrAdasHmi").mkdirs(); java.io.File(args[0]).copyTo(java.io.File(root, "ZeekrAdasHmi/ZeekrAdasHmi.apk"))
        val dex = java.util.zip.ZipFile(args[0]).use { z -> z.getInputStream(z.getEntry("classes.dex")).readBytes() }
        java.io.File(root, "Stripped/oat/arm64").mkdirs(); java.io.File(root, "Stripped/Stripped.apk").writeBytes(java.io.File(args[0]).readBytes().copyOf(0))
        java.io.File(root, "Stripped/oat/arm64/Stripped.vdex").writeBytes(ByteArray(64) + dex)
        if (args.size > 1) { java.io.File(root, "ZeekrVehicleService").mkdirs(); java.io.File(args[1]).copyTo(java.io.File(root, "ZeekrVehicleService/ZeekrVehicleService.apk")) }
        au.local.zeekr.srprobe.platform.SystemFiles.appDirsOverride = listOf(root.path, "/nonexistent/app")
        val man = au.local.zeekr.srprobe.platform.ManifestReader.components(
            java.util.zip.ZipFile(args[0]).use { z -> z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes() })
        println("manifest: " + man.joinToString(" | "))
        check(man.any { it.contains("provider") && it.contains("authorities=au.local.zeekr.srprobe.reports") && it.contains("exported=false") }, "manifest walker reads provider attributes")
    }
    val vm = au.local.zeekr.srprobe.ui.DiagnosticsViewModel(FakeContext())
    vm.runSafeDiscovery()
    var waited = 0
    while (vm.discoveryMs == 0L && waited++ < 200) Thread.sleep(100)
    check(vm.discoveryMs > 0, "discovery pipeline finished (errors: ${vm.errors.size})")
    vm.errors.forEach { println("  discovery note: " + it.take(140)) }
    val ex = au.local.zeekr.srprobe.logging.ReportExporter(FakeContext(), vm)
    val md = ex.markdown(); val sum = ex.summary(); val js = ex.discoveryJson().toString()
    check(md.contains("## Known vehicle signals") && md.contains("Read-only invocation ledger"), "markdown report builds (${md.length} chars)")
    check(sum.contains("SURROUNDING-CAR LEADS") && sum.contains("ECARX: car AVAILABLE"), "summary builds (${sum.lines().size} lines)")
    if (args.isNotEmpty()) {
        check(vm.appFolders == (if (args.size > 1) 3 else 2), "app folder scan found its folders: ${vm.appScanNote}")
        check(vm.dexScans.any { it.source == "Stripped (vdex)" && it.totalClasses > 100 }, "stripped app scanned through its vdex")
        check(vm.dexScans.any { it.source == "ZeekrAdasHmi" && it.dexFiles > 0 }, "app APK scanned by folder")
        if (args.size > 1) {
            val sr = vm.srInspect.flatMap { it.classes }.firstOrNull { it.name == "com.zeekr.sdk.adcu.bean.SRObject" }
            println("SRObject detail: $sr")
            check(sr != null && "float posX" in sr.fields && sr.methods.any { it == "float getPosX()" } && "Serializable" in sr.interfaces,
                "SR inspector lists SRObject fields, methods and interfaces")
            check(sum.contains("SR OBJECT DETAILS") && sum.contains("f float posY"), "summary shows SR object fields")
        }
    }
    check(js.contains("signals"), "discovery json builds")
    check(Calls.log.none { it.startsWith("MUTATOR") || it.startsWith("UNVERIFIED") }, "still no mutator after full pipeline")
    println(sum.lines().take(40).joinToString("\n"))
    println("SMOKE TEST PASSED")
}
