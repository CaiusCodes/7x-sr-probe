package au.local.zeekr.srprobe.platform

import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard
import java.io.File

/**
 * v0.2: finds system APKs and config file names by directory listing (READ_ONLY_AUDIT.md section B).
 * App Lab's PackageManager shows this app only a handful of packages, but the system partitions are
 * listable. Nothing here opens a config file's contents or touches a package.
 */
object SystemFiles {

    data class AppFolder(val folder: String, val apks: List<String>, val vdex: List<String>)

    val APP_DIRS = listOf(
        "/system/app", "/system/priv-app", "/system_ext/app", "/system_ext/priv-app",
        "/product/app", "/product/priv-app", "/vendor/app", "/odm/app"
    )
    private val ETC_DIRS = listOf("/system/etc", "/system_ext/etc", "/product/etc", "/vendor/etc", "/odm/etc")
    private val ETC_TERMS = Terms.PACKAGE + listOf("someip", "vsomeip", "dds", "fastdds", "fusion", "hmi", "ihu", "proto", "ipc", "vdc", "radar")

    /** Test hook (JVM smoke test only); null on the car. */
    @Volatile var appDirsOverride: List<String>? = null

    /** Per listed dir: "ok N" or "not listable". */
    val dirNotes = LinkedHashMap<String, String>()

    fun appFolders(): List<AppFolder> {
        ReadOnlyGuard.count("file:File.list(system app dirs)")
        val out = ArrayList<AppFolder>()
        for (d in appDirsOverride ?: APP_DIRS) {
            val subs = runCatching { File(d).listFiles()?.toList() }.getOrNull()
            dirNotes[d] = if (subs == null) "not listable" else "${subs.size} entries"
            for (sub in subs.orEmpty().sortedBy { it.name }) {
                if (sub.isFile && sub.name.endsWith(".apk")) { out += AppFolder(sub.path, listOf(sub.path), emptyList()); continue }
                if (!sub.isDirectory) continue
                val apks = runCatching { sub.listFiles()?.filter { it.name.endsWith(".apk") }?.map { it.path } }.getOrNull().orEmpty()
                val vdex = runCatching {
                    File(sub, "oat").listFiles()?.filter { it.isDirectory }?.flatMap { isa ->
                        isa.listFiles()?.filter { it.name.endsWith(".vdex") }?.map { it.path }.orEmpty()
                    }
                }.getOrNull().orEmpty()
                if (apks.isNotEmpty() || vdex.isNotEmpty()) out += AppFolder(sub.path, apks.sorted(), vdex.sorted())
            }
        }
        return out
    }

    /** Config file paths (two levels) whose names match a relevance term. Names only. */
    fun configNames(): List<String> {
        ReadOnlyGuard.count("file:File.list(etc dirs)")
        val out = ArrayList<String>()
        for (d in ETC_DIRS) {
            val top = runCatching { File(d).listFiles()?.toList() }.getOrNull() ?: continue
            for (f in top) {
                val children = if (f.isDirectory) runCatching { f.listFiles()?.toList() }.getOrNull().orEmpty() else emptyList()
                for (c in listOf(f) + children) {
                    val rel = c.path
                    if (Terms.match(c.name.substringBeforeLast('.'), ETC_TERMS).isNotEmpty() || Terms.match(f.name, ETC_TERMS).isNotEmpty() && c != f)
                        out += rel + if (c.isDirectory) "/" else ""
                }
            }
        }
        return out.distinct().sorted().take(400)
    }

    /** Scan order: names that look vehicle/ADAS/cluster related first, then everything else. */
    fun priority(folder: AppFolder): Int {
        val n = folder.folder.substringAfterLast('/')
        return Terms.match(n, Terms.STRONG).size * 4 + Terms.match(n, Terms.PACKAGE).size + if (Terms.perceptionScore(n) >= 2) 4 else 0
    }
}
