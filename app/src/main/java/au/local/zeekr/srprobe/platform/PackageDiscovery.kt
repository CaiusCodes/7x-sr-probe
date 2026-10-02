package au.local.zeekr.srprobe.platform

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import au.local.zeekr.srprobe.model.ComponentRecord
import au.local.zeekr.srprobe.model.PackageRecord
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard

/**
 * Package discovery (brief §7) through normal PackageManager reads.
 *
 * Never starts, binds, queries or otherwise touches a component: the lists below are metadata from
 * PackageInfo. Component names are recorded so a human can look at them later.
 */
object PackageDiscovery {

    data class Result(
        val totalVisible: Int,
        val allPackageNames: List<String>,
        val relevant: List<PackageRecord>,
        val error: String?
    )

    @Suppress("DEPRECATION")
    fun run(context: Context): Result {
        val pm = context.packageManager
        val all: List<PackageInfo> = try {
            ReadOnlyGuard.count("framework:PackageManager.getInstalledPackages(0)")
            pm.getInstalledPackages(0)
        } catch (t: Throwable) {
            return Result(0, emptyList(), emptyList(), ReadOnlyGuard.describe(t))
        }
        val names = all.map { it.packageName }.sorted()
        val relevant = ArrayList<PackageRecord>()
        for (name in names) {
            val label = runCatching { all.first { it.packageName == name }.applicationInfo?.loadLabel(pm)?.toString() }.getOrNull()
            val terms = (Terms.match(name, Terms.PACKAGE) + Terms.match(label ?: "", Terms.PACKAGE)).distinct()
            if (terms.isEmpty() || name == context.packageName) continue
            relevant += describe(pm, name, label, terms)
        }
        return Result(all.size, names, relevant, null)
    }

    @Suppress("DEPRECATION")
    private fun describe(pm: PackageManager, name: String, label: String?, terms: List<String>): PackageRecord {
        // Ask for each component type separately: one big query can exceed the binder transaction limit.
        val base = runCatching { pm.getPackageInfo(name, PackageManager.GET_PERMISSIONS) }
        val info = base.getOrNull()
        fun comps(flag: Int, pick: (PackageInfo) -> Array<out ComponentInfo>?): List<ComponentRecord> =
            runCatching {
                ReadOnlyGuard.count("framework:PackageManager.getPackageInfo(pkg, flags)")
                val pi = pm.getPackageInfo(name, flag or PackageManager.MATCH_DISABLED_COMPONENTS)
                (pick(pi) ?: emptyArray<ComponentInfo>()).map { c ->
                    val perm = when (c) {
                        is android.content.pm.ServiceInfo -> c.permission
                        is android.content.pm.ActivityInfo -> c.permission
                        is android.content.pm.ProviderInfo -> c.readPermission
                        else -> null
                    }
                    ComponentRecord(
                        name = c.name,
                        exported = c.exported,
                        enabled = c.enabled,
                        permission = perm,
                        authority = (c as? android.content.pm.ProviderInfo)?.authority
                    )
                }.sortedBy { it.name }
            }.getOrElse { emptyList() }

        val app: ApplicationInfo? = info?.applicationInfo
        return PackageRecord(
            packageName = name,
            label = label,
            versionName = info?.versionName,
            versionCode = if (Build.VERSION.SDK_INT >= 28) info?.longVersionCode ?: -1 else (info?.versionCode ?: -1).toLong(),
            enabled = app?.enabled ?: false,
            system = app != null && (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            sourceDir = app?.sourceDir,
            matchedTerms = terms,
            activities = comps(PackageManager.GET_ACTIVITIES) { it.activities },
            services = comps(PackageManager.GET_SERVICES) { it.services },
            receivers = comps(PackageManager.GET_RECEIVERS) { it.receivers },
            providers = comps(PackageManager.GET_PROVIDERS) { it.providers },
            requestedPermissions = info?.requestedPermissions?.toList()?.sorted() ?: emptyList(),
            error = base.exceptionOrNull()?.let { ReadOnlyGuard.describe(it) }
        )
    }
}
