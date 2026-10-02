package au.local.zeekr.srprobe.ecarx

import au.local.zeekr.srprobe.model.Availability
import au.local.zeekr.srprobe.model.DiscoveredApi
import au.local.zeekr.srprobe.model.ReadKind
import au.local.zeekr.srprobe.model.Terms

/**
 * Turns reflected adapt-API constants into a catalogue of SDK-declared ids whose NAMES relate to ADAS,
 * perception, lanes, targets, blind spots or traffic lights (brief §11).
 *
 * Default behaviour: catalogue only. Nothing is read.
 *
 * Opt-in (separate button, parked only): read each catalogued id ONCE with the same allowlisted getters used
 * for known signals. These are ids the SDK itself names, not guessed numbers or ranges, and the getters
 * return the car service's cached value. No setter, no customise call, no zone sweep.
 */
object SensorDiscovery {

    data class NamedConstant(
        val declaringClass: String,
        val name: String,
        val value: Int,
        val matchedTerms: List<String>,
        /** Which getter a later opt-in read would use, or null if the name does not say. */
        val readAs: List<ReadKind>
    )

    data class NamedRead(val constant: NamedConstant, val kind: ReadKind, val availability: Availability, val raw: String?, val error: String?)

    private val ADAS_TERMS = Terms.STRONG + listOf("adas", "acc", "lane", "ldw", "lkas", "fcw", "rcw", "rcta", "fcta", "dow",
        "bsm", "bsd", "lca", "ihc", "tsr", "tla", "tlr", "sign", "traffic", "obj", "obs", "target", "track",
        "radar", "avm", "apa", "rpa", "hwa", "nzp", "noa", "pilot", "cruise", "distance", "ttc",
        "pedestrian", "cyclist", "object", "scene", "sr")

    private const val MAX_OPT_IN_READS = 400

    /** Names that announce which getter applies. Anything else is catalogued but never read. */
    private fun readKinds(cls: String, field: String): List<ReadKind> {
        val f = field.uppercase()
        val c = cls.substringAfterLast('.')
        return when {
            "FUNC" in f || c.contains("Function", true) -> listOf(ReadKind.FUNCTION)
            f.startsWith("SENSOR_TYPE") || c.contains("Sensor", true) -> listOf(ReadKind.SENSOR_EVENT, ReadKind.SENSOR_VALUE)
            else -> emptyList()
        }
    }

    fun catalogue(apis: List<DiscoveredApi>): List<NamedConstant> {
        val out = ArrayList<NamedConstant>()
        for (api in apis) {
            if (!api.className.startsWith("com.ecarx") && !api.className.startsWith("ecarx.")) continue
            for (f in api.fields) {
                if (f.type != "int" || f.constantValue == null) continue
                val v = f.constantValue.substringBefore(' ').toIntOrNull() ?: continue
                val terms = Terms.match(f.name, ADAS_TERMS)
                if (terms.isEmpty()) continue
                out += NamedConstant(api.className, f.name, v, terms, readKinds(api.className, f.name))
            }
        }
        return out.distinctBy { it.name to it.value }.sortedBy { it.declaringClass + "#" + it.name }
    }

    /** Opt-in only. Reads each readable id once. Ids below 0x00100000 are enum values, not signal ids: skipped. */
    fun readCatalogueOnce(reader: VehicleSignalReader, catalogue: List<NamedConstant>): List<NamedRead> {
        val out = ArrayList<NamedRead>()
        val done = HashSet<String>()
        for (c in catalogue) {
            if (c.value < 0x00100000) continue
            for (k in c.readAs) {
                if (!done.add("$k:${c.value}")) continue
                if (out.size >= MAX_OPT_IN_READS) return out
                val r = reader.read(k, c.value, 0)
                out += NamedRead(c, k, r.availability, KnownSignal.rawString(r.value), r.error)
            }
        }
        return out
    }
}
