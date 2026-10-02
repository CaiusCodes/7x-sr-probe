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
    println("vehicle calls: " + Calls.log.groupingBy { it.substringBefore('(') }.eachCount())
    println("ledger: " + ReadOnlyGuard.ledgerSnapshot())

    if (args.isNotEmpty()) {
        val r = DexScanner.scan("apk", args[0])
        check(r.totalClasses > 100, "dex parser read ${r.totalClasses} classes from the built APK")
    }
    // Whole pipeline: discovery steps (most fail harmlessly without a real PackageManager) then every export format.
    val vm = au.local.zeekr.srprobe.ui.DiagnosticsViewModel(FakeContext())
    vm.runSafeDiscovery()
    var waited = 0
    while (vm.discoveryMs == 0L && waited++ < 200) Thread.sleep(100)
    check(vm.discoveryMs > 0, "discovery pipeline finished (errors: ${vm.errors.size})")
    vm.errors.forEach { println("  discovery note: " + it.take(140)) }
    val ex = au.local.zeekr.srprobe.logging.ReportExporter(FakeContext(), vm)
    val md = ex.markdown(); val sum = ex.summary(); val js = ex.discoveryJson().toString()
    check(md.contains("## Known vehicle signals") && md.contains("Read-only invocation ledger"), "markdown report builds (${md.length} chars)")
    check(sum.contains("SIGNALS") && sum.contains("ECARX: car AVAILABLE"), "summary builds (${sum.lines().size} lines)")
    check(js.contains("signals"), "discovery json builds")
    check(Calls.log.none { it.startsWith("MUTATOR") || it.startsWith("UNVERIFIED") }, "still no mutator after full pipeline")
    println(sum.lines().take(14).joinToString("\n"))
    println("SMOKE TEST PASSED")
}
