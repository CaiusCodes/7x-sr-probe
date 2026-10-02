package au.local.zeekr.srprobe.platform

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Process
import android.util.DisplayMetrics
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.io.File
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Runtime environment (brief §6). Public Android APIs first; then read-only platform identification that
 * survives App Lab's Build.* spoofing (system properties, BOOTCLASSPATH, framework jar names).
 *
 * Nothing here attempts to bypass the container. If Build.* is spoofed, both views are reported.
 */
object AndroidEnvironment {

    data class Section(val title: String, val rows: List<Pair<String, String>>)

    /** System property keys/prefixes worth reporting. Private-looking keys are always dropped. */
    private val PROP_PREFIXES = listOf(
        "ro.build.", "ro.product.", "ro.board.", "ro.hardware", "ro.boot.hardware", "ro.soc.", "ro.vendor.build.",
        "ro.system.build.", "ro.odm.build.", "ro.ecarx", "ro.zeekr", "ro.geely", "persist.ecarx", "persist.zeekr",
        "ro.car", "ro.vehicle", "ro.hmi", "ro.cluster", "ro.config.", "ro.debuggable", "ro.secure",
        "ro.treble.", "ro.vndk.", "ro.carrier", "ro.oem", "ro.vlite", "ro.applab"
    )

    fun collect(context: Context): List<Section> {
        val out = ArrayList<Section>()
        val pm = context.packageManager
        val self = runCatching { pm.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS) }.getOrNull()

        out += Section("App", listOf(
            "Package" to context.packageName,
            "Version" to "${self?.versionName} (${if (Build.VERSION.SDK_INT >= 28) self?.longVersionCode else @Suppress("DEPRECATION") self?.versionCode})",
            "Process UID" to Process.myUid().toString(),
            "Process PID" to Process.myPid().toString(),
            "Target SDK" to context.applicationInfo.targetSdkVersion.toString(),
            "Source dir" to (context.applicationInfo.sourceDir ?: "?"),
            "Data dir" to (context.applicationInfo.dataDir ?: "?"),
            "Class loader" to (javaClass.classLoader?.javaClass?.name ?: "?")
        ))

        out += Section("Android (public Build.* — may be spoofed by App Lab)", listOf(
            "Android release" to Build.VERSION.RELEASE,
            "SDK level" to Build.VERSION.SDK_INT.toString(),
            "Security patch" to (if (Build.VERSION.SDK_INT >= 23) Build.VERSION.SECURITY_PATCH else "?"),
            "Manufacturer" to Build.MANUFACTURER,
            "Brand" to Build.BRAND,
            "Model" to Build.MODEL,
            "Product" to Build.PRODUCT,
            "Device" to Build.DEVICE,
            "Board" to Build.BOARD,
            "Hardware" to Build.HARDWARE,
            "Display id" to Build.DISPLAY,
            "Fingerprint" to Build.FINGERPRINT,
            "Type / tags" to "${Build.TYPE} / ${Build.TAGS}",
            "Supported ABIs" to Build.SUPPORTED_ABIS.joinToString(),
            "Uptime (incl. deep sleep)" to "${TimeUnit.MILLISECONDS.toMinutes(android.os.SystemClock.elapsedRealtime())} min"
        ))

        out += Section("Platform identity (read-only system properties)", readProperties())

        out += Section("Displays", displays(context))

        val locale = Locale.getDefault()
        out += Section("Locale", listOf("Locale" to locale.toString(), "Time zone" to java.util.TimeZone.getDefault().id))

        out += Section("Permissions (this app)", permissions(context, self?.requestedPermissions))

        out += Section("Class paths (environment variables)", listOf(
            "BOOTCLASSPATH" to (System.getenv("BOOTCLASSPATH") ?: "(not set)"),
            "SYSTEMSERVERCLASSPATH" to (System.getenv("SYSTEMSERVERCLASSPATH") ?: "(not set)")
        ))

        out += Section("Framework jars (directory listing only)", frameworkJars())

        out += Section("Container hints", containerHints(context))

        val features = runCatching { pm.systemAvailableFeatures.mapNotNull { it.name }.sorted() }.getOrElse { emptyList() }
        out += Section("System features (${features.size})", features.map { it to "" })
        return out
    }

    private fun displays(context: Context): List<Pair<String, String>> {
        val rows = ArrayList<Pair<String, String>>()
        val res = context.resources
        val cfg = res.configuration
        rows += "App config" to "${cfg.screenWidthDp}x${cfg.screenHeightDp} dp, density ${res.displayMetrics.densityDpi} dpi, " +
            "orientation ${if (cfg.orientation == 2) "landscape" else if (cfg.orientation == 1) "portrait" else "undefined"}"
        // DisplayManager.getDisplays() is a public read. A cluster or HUD display may appear here.
        val dm = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
        val all = runCatching { dm?.displays?.toList() ?: emptyList() }.getOrElse { emptyList() }
        for (d in all) {
            val m = DisplayMetrics()
            @Suppress("DEPRECATION") d.getRealMetrics(m)
            rows += "Display ${d.displayId}" to "\"${d.name}\" ${m.widthPixels}x${m.heightPixels} @${m.densityDpi}dpi, " +
                "refresh ${"%.1f".format(Locale.US, d.refreshRate)} Hz, flags 0x${Integer.toHexString(d.flags)}, state ${d.state}"
        }
        if (all.isEmpty()) rows += "Displays" to "none visible"
        return rows
    }

    private fun permissions(context: Context, requested: Array<String>?): List<Pair<String, String>> {
        val list = (requested?.toList() ?: emptyList()) + listOf(
            // Not requested; checked to document what the container grants by default.
            "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.car.permission.CAR_SPEED", "android.car.permission.CAR_POWERTRAIN",
            "android.car.permission.CAR_INFO", "android.car.permission.CAR_EXTERIOR_ENVIRONMENT"
        )
        return list.distinct().map { p ->
            p to if (context.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED) "GRANTED" else "DENIED"
        }
    }

    /**
     * Reads properties with SystemProperties.get(key) by reflection (a hidden but app-accessible read).
     * The candidate key list comes from one `getprop` listing, which only prints; it cannot set anything.
     * Keys that look private (serial, VIN, MAC, account...) are dropped before anything is stored.
     */
    fun readProperties(): List<Pair<String, String>> {
        val rows = ArrayList<Pair<String, String>>()
        val all = getpropListing()
        if (all.isNotEmpty()) {
            for ((k, v) in all) {
                if (Terms.isPrivateKey(k)) continue
                if (PROP_PREFIXES.none { k.startsWith(it) }) continue
                rows += k to Terms.redact(v)
            }
            rows += "(getprop)" to "${all.size} properties visible, ${rows.size} reported after filtering"
            return rows
        }
        val get = runCatching {
            Class.forName("android.os.SystemProperties").getMethod("get", String::class.java)
        }.getOrNull()
        for (k in listOf("ro.build.display.id", "ro.board.platform", "ro.hardware", "ro.product.board",
            "ro.build.version.release", "ro.build.type", "ro.vendor.build.fingerprint", "ro.boot.hardware")) {
            val v = runCatching { ReadOnlyGuard.invokeFramework(get!!, null, k) as? String }.getOrNull()
            rows += k to (v?.takeIf { it.isNotEmpty() }?.let { Terms.redact(it) } ?: "(unreadable)")
        }
        rows += "(getprop)" to "listing unavailable; fell back to SystemProperties.get for a fixed key list"
        return rows
    }

    /** `getprop` with no arguments only prints properties. Runs as this app's own unprivileged UID. */
    private fun getpropListing(): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        try {
            ReadOnlyGuard.count("exec:/system/bin/getprop (no arguments)")
            val p = ProcessBuilder("/system/bin/getprop").redirectErrorStream(true).start()
            val regex = Regex("^\\[(.+?)]: \\[(.*)]$")
            p.inputStream.bufferedReader().useLines { lines ->
                lines.take(20000).forEach { line ->
                    regex.matchEntire(line)?.let { out[it.groupValues[1]] = it.groupValues[2] }
                }
            }
            p.waitFor(5, TimeUnit.SECONDS)
            p.destroy()
        } catch (_: Throwable) {
        }
        return out
    }

    private fun frameworkJars(): List<Pair<String, String>> {
        val rows = ArrayList<Pair<String, String>>()
        for (d in listOf("/system/framework", "/system_ext/framework", "/product/framework", "/vendor/framework", "/odm/framework")) {
            val names = runCatching { File(d).list()?.filter { it.endsWith(".jar") || it.endsWith(".apk") }?.sorted() }.getOrNull()
            rows += d to when {
                names == null -> "(not listable)"
                names.isEmpty() -> "(no jars)"
                else -> names.joinToString(", ")
            }
        }
        return rows
    }

    private fun containerHints(context: Context): List<Pair<String, String>> {
        val rows = ArrayList<Pair<String, String>>()
        // Class.forName(name, initialize = false): checks presence without running any static initialiser.
        for (c in listOf("com.vlite.sdk.proxy.StubService", "com.vlite.sdk.VLite", "android.car.Car",
            ReadOnlyGuard.ECARX_CAR_CLASS)) {
            rows += c to if (runCatching { Class.forName(c, false, javaClass.classLoader) }.isSuccess) "present" else "absent"
        }
        val procName = if (Build.VERSION.SDK_INT >= 28) android.app.Application.getProcessName() else "?"
        rows += "Process name" to procName
        rows += "Files dir" to context.filesDir.absolutePath
        return rows
    }
}
