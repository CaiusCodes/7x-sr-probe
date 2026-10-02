package au.local.zeekr.srprobe.platform

import android.os.IBinder
import au.local.zeekr.srprobe.model.ServiceRecord
import au.local.zeekr.srprobe.model.Terms
import au.local.zeekr.srprobe.safety.ReadOnlyGuard

/**
 * Binder service discovery (brief §4.4).
 *
 * 1. ServiceManager.listServices(): names registered with servicemanager (read-only lookup).
 * 2. OPT-IN (off by default, a UI toggle): for names matching a relevance term only,
 *    ServiceManager.checkService(name) to get the IBinder,
 *    then IBinder.getInterfaceDescriptor(). That sends the standard INTERFACE_TRANSACTION meta-call,
 *    which the Binder base class answers with the AIDL interface name before any service code runs.
 *
 * No other transaction is ever sent. No service method is called. pingBinder/dump are not used.
 */
object ServiceDiscovery {

    data class Result(val totalServices: Int, val relevant: List<ServiceRecord>, val allNames: List<String>, val note: String?)

    private val SERVICE_TERMS = Terms.PACKAGE + Terms.CLASS + listOf("ecarx", "zeekr", "carsecurity", "vehicledc")

    fun run(queryDescriptors: Boolean): Result {
        val sm = runCatching { Class.forName("android.os.ServiceManager") }.getOrNull()
            ?: return Result(0, emptyList(), emptyList(), "android.os.ServiceManager not accessible")
        val names: List<String> = try {
            val list = sm.getMethod("listServices")
            @Suppress("UNCHECKED_CAST")
            (ReadOnlyGuard.invokeFramework(list, null) as? Array<String>)?.toList()?.sorted() ?: emptyList()
        } catch (t: Throwable) {
            return Result(0, emptyList(), emptyList(), "listServices failed: ${ReadOnlyGuard.describe(t)}")
        }
        val check = if (queryDescriptors) runCatching { sm.getMethod("checkService", String::class.java) }.getOrNull() else null
        val relevant = ArrayList<ServiceRecord>()
        for (n in names) {
            val terms = Terms.match(n, SERVICE_TERMS)
            if (terms.isEmpty()) continue
            var descriptor: String? = null
            var note: String? = null
            if (check != null) {
                try {
                    val binder = ReadOnlyGuard.invokeFramework(check, null, n) as? IBinder
                    if (binder == null) {
                        note = "checkService returned null (not visible to this UID)"
                    } else {
                        ReadOnlyGuard.count("binder:IBinder.getInterfaceDescriptor() [INTERFACE_TRANSACTION]")
                        descriptor = binder.interfaceDescriptor
                    }
                } catch (t: Throwable) {
                    note = ReadOnlyGuard.describe(t)
                }
            }
            relevant += ServiceRecord(n, descriptor, terms, note)
        }
        val note = when {
            !queryDescriptors -> "Interface descriptors not queried (opt-in toggle was off); names only"
            check == null -> "checkService not accessible; names only"
            else -> null
        }
        return Result(names.size, relevant, names, note)
    }
}
