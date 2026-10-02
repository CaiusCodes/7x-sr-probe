package au.local.zeekr.srprobe.model

/**
 * Relevance terms from the project brief (sections 7 and 8), plus render-engine hints for spotting
 * a hidden SR/scene renderer. Matching is name-based only; nothing is executed because it matched.
 */
object Terms {

    /** Brief §7, package filter. */
    val PACKAGE = listOf(
        "zeekr", "ecarx", "geely", "vision", "visual", "sr", "scene", "adas", "pilot", "drive", "driver",
        "cluster", "hud", "avm", "surround", "camera", "map", "navigation", "navi", "vehicle", "car",
        "sensor", "perception", "obstacle", "lane", "traffic", "object", "target", "mobileye", "nvidia"
    )

    /** Brief §8, class/member filter. */
    val CLASS = listOf(
        "adas", "pilot", "perception", "vision", "scene", "sr", "surround", "object", "obstacle", "target",
        "track", "vehicle", "pedestrian", "cyclist", "motorcycle", "truck", "bus", "lane", "laneline", "road",
        "traffic", "trafficlight", "sign", "blind", "bsd", "acc", "aeb", "lka", "lcc", "nzp", "noa", "sensor",
        "environment", "camera", "cluster", "hud", "display", "radar", "lidar", "fusion", "avm", "apa"
    )

    /** Terms that point at perception/scene data specifically (used to rank "candidate perception APIs"). */
    val STRONG = listOf(
        "perception", "obstacle", "pedestrian", "cyclist", "motorcycle", "lane", "laneline", "trafficlight",
        "adas", "pilot", "nzp", "noa", "bsd", "blind", "acc", "aeb", "lcc", "lka", "scene", "sr", "surround",
        "radar", "lidar", "fusion", "vision", "target", "envmodel", "worldmodel"
    )

    /**
     * v0.2 surrounding-traffic scoring, token based so "JsonObject" scores only the weak "object".
     * Strong tokens point at perception output; weak ones need a second hit before a name is listed.
     */
    private val PERCEPTION_STRONG = setOf(
        "perception", "obstacle", "obstacles", "fusion", "ego", "freespace", "cipv", "vru", "envmodel", "worldmodel",
        "surrounding", "pedestrian", "pedestrians", "cyclist", "cyclists", "laneline", "lanelines", "roadmodel",
        "radar", "lidar", "sr", "objlist", "objectlist", "hdmap"
    )
    private val PERCEPTION_WEAK = setOf(
        "obj", "objs", "object", "objects", "target", "targets", "track", "tracks", "tracking", "lane", "lanes",
        "traffic", "vehicle", "vehicles", "adas", "pilot", "scene", "surround", "cluster", "hud", "dashboard",
        "nzp", "noa", "acc"
    )

    /** 0 = unrelated. Strong token = 2, weak token = 1; a name is listed at 2 or more. */
    fun perceptionScore(name: String): Int {
        if (isCommonLib(name)) return 0
        val toks = tokens(name.substringAfterLast('.'))
        val strong = toks.count { it in PERCEPTION_STRONG }
        val weak = toks.count { it in PERCEPTION_WEAK }
        if (strong > 0) return strong * 2 + weak
        // Weak-only names: two hits in vendor code (e.g. "AdasTarget"), three anywhere else.
        return if (weak >= 3 || (weak >= 2 && isVendor(name))) weak else 0
    }

    /** Native-library / asset hints for a 3D cluster or SR renderer. */
    val RENDER = listOf(
        "unity", "unreal", "ue4", "ue5", "kanzi", "godot", "cocos", "filament", "osg", "sr", "scene", "hmi3d",
        "3d", "truck", "bus", "pedestrian", "cyclist", "cone", "fbx", "glb", "gltf", "obj"
    )

    /** Namespaces we treat as vehicle-vendor code. */
    val VENDOR_PREFIXES = listOf(
        "com.ecarx", "ecarx.", "com.zeekr", "zeekr.", "com.zeekrlife", "com.geely", "geely.", "com.lynkco",
        "android.car", "com.android.car", "com.mobileye", "com.nvidia", "com.horizon", "com.momenta",
        "vendor.zeekr", "vendor.ecarx"
    )

    /** Library namespaces that only produce noise. */
    val COMMON_LIB_PREFIXES = listOf(
        "android.", "androidx.", "kotlin", "java.", "javax.", "com.google.", "okhttp3.", "okio.", "retrofit2.",
        "io.reactivex", "org.json", "org.apache", "com.squareup", "dagger.", "com.bumptech", "com.facebook",
        "org.intellij", "org.jetbrains", "sun.", "dalvik.", "libcore.", "org.xmlpull", "org.w3c", "org.xml"
    )

    private val SPLIT = Regex("(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|[^A-Za-z0-9]+")

    fun tokens(s: String): List<String> = s.split(SPLIT).filter { it.isNotEmpty() }.map { it.lowercase() }

    /**
     * Terms of four letters or fewer must match a whole token (or its plural) so "sr" does not match
     * "user" and "sign" does not match "signature". Longer terms match as substrings.
     */
    fun match(s: String, terms: List<String>): List<String> {
        if (s.isEmpty()) return emptyList()
        val toks = tokens(s)
        val lower = s.lowercase()
        return terms.filter { t ->
            if (t.length <= 4) toks.any { it == t || it == t + "s" } else lower.contains(t)
        }
    }

    fun isVendor(className: String): Boolean = VENDOR_PREFIXES.any { className.startsWith(it) }

    fun isCommonLib(className: String): Boolean =
        COMMON_LIB_PREFIXES.any { className.startsWith(it) } && !className.startsWith("android.car")

    /** A class name worth listing: vendor code matching any term, or non-library code matching a strong term. */
    fun isRelevantClass(className: String): Boolean {
        if (isVendor(className)) return match(className, CLASS).isNotEmpty()
        if (isCommonLib(className)) return false
        return match(className, STRONG).isNotEmpty()
    }

    /** Things that must never end up in a report even if they match a term. */
    private val PRIVATE_KEY = Regex("(?i)(serial|vin|imei|iccid|imsi|msisdn|mac|bt\\.addr|bdaddr|wifi|token|password|passwd|secret|account|phone|sim|email|key|cert|uuid)")
    private val VIN_LIKE = Regex("\\b[A-HJ-NPR-Z0-9]{17}\\b")

    fun isPrivateKey(key: String): Boolean = PRIVATE_KEY.containsMatchIn(key)

    fun redact(value: String): String = VIN_LIKE.replace(value, "[redacted-17-char-id]")
}
