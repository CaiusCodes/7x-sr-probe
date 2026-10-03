package au.local.zeekr.srprobe.platform

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * v0.6: finds the paths the vehicle data provider answers to, by reading the provider app's dex as bytes
 * (READ_ONLY_AUDIT.md section G). A provider usually registers paths as string constants passed to
 * UriMatcher.addURI, so we list the const-string operands inside every ContentProvider subclass (and its
 * nested and contract-style classes in the same package). Nothing is loaded or run.
 */
object ProviderPaths {

    data class Found(val source: String, val providerClasses: List<String>, val strings: List<String>, val fullUris: List<String>, val note: String?)

    private const val MAX_BYTES = 96L * 1024 * 1024
    private const val MAX_STRINGS = 200
    private val CONTRACT = Regex("Contract|Uri|Const|Column|Table|Path|Matcher")
    private val PATH = Regex("^[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z0-9_#*]+)*$")

    /** Paths under [authority] worth querying: vendor strings, wildcard segments cut off, capped. */
    fun candidatePaths(found: List<Found>, authority: String, cap: Int = 40): List<String> {
        val out = LinkedHashSet<String>()
        found.flatMap { it.fullUris }.forEach { out += it.trimEnd('/') }
        for (s in found.flatMap { it.strings }) {
            if (s == authority || s.length < 2 || s.length > 60 || !PATH.matches(s)) continue
            val segs = s.split('/').takeWhile { it != "#" && it != "*" }
            if (segs.isNotEmpty()) out += "content://$authority/" + segs.joinToString("/")
        }
        return out.take(cap)
    }

    /** Folders under the system app dirs named like the provider's app, plus any extra paths given. */
    fun inspect(appName: String, extraPaths: List<String>, authority: String): List<Found> {
        val paths = LinkedHashSet<String>()
        runCatching { SystemFiles.appFolders() }.getOrNull().orEmpty()
            .filter { File(it.folder).name.removeSuffix(".apk") == appName }
            .forEach { paths += it.apks; paths += it.vdex }
        paths += extraPaths
        return paths.map { inspectOne(it, authority) }
    }

    fun inspectOne(path: String, authority: String): Found {
        val f = File(path)
        if (!f.canRead()) return Found(path, emptyList(), emptyList(), emptyList(), "not readable")
        val providers = LinkedHashSet<String>(); val strings = LinkedHashSet<String>(); val uris = LinkedHashSet<String>()
        var note: String? = null
        try {
            dexImages(f).forEach { parse(it, authority, providers, strings, uris) }
        } catch (t: Throwable) { note = "${t.javaClass.simpleName}: ${t.message}" }
        if (providers.isEmpty() && note == null) note = "no ContentProvider subclass in readable dex"
        return Found(path, providers.toList(), strings.take(MAX_STRINGS), uris.toList(), note)
    }

    private fun dexImages(f: File): List<ByteArray> {
        if (f.length() > MAX_BYTES) return emptyList()
        if (f.name.endsWith(".vdex") || f.name.endsWith(".odex")) {
            val bytes = f.readBytes(); val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val out = ArrayList<ByteArray>(); var i = 0
            while (i + 0x70 <= bytes.size) {
                if (bytes[i] == 'd'.code.toByte() && bytes[i + 1] == 'e'.code.toByte() && bytes[i + 2] == 'x'.code.toByte() && bytes[i + 3] == '\n'.code.toByte()) {
                    val size = b.getInt(i + 0x20)
                    if (size >= 0x70 && i.toLong() + size <= bytes.size) { out += bytes.copyOfRange(i, i + size); i += size; continue }
                }
                i++
            }
            return out
        }
        return ZipFile(f).use { zip ->
            zip.entries().toList().filter { Regex("classes\\d*\\.dex").matches(it.name) }
                .map { e -> zip.getInputStream(e).use { it.readBytes() } }
        }
    }

    private fun parse(dex: ByteArray, authority: String, providers: MutableSet<String>, strings: MutableSet<String>, uris: MutableSet<String>) {
        if (dex.size < 0x70 || dex[0] != 'd'.code.toByte()) return
        val b = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = b.getInt(0x38)
        val stringIdsOff = b.getInt(0x3C)
        val typeIdsOff = b.getInt(0x44)
        val classDefsSize = b.getInt(0x60)
        val classDefsOff = b.getInt(0x64)
        fun str(idx: Int): String {
            var p = b.getInt(stringIdsOff + idx * 4)
            while (dex[p].toInt() and 0x80 != 0) p++
            p++
            var end = p
            while (end < dex.size && dex[end].toInt() != 0) end++
            return String(dex, p, end - p, Charsets.UTF_8)
        }
        fun type(idx: Int): String = str(b.getInt(typeIdsOff + idx * 4))

        val prefix = "content://$authority"
        for (i in 0 until stringIdsSize) { val s = str(i); if (s.startsWith(prefix)) uris += s }

        // Pass 1: ContentProvider subclasses.
        val names = Array(classDefsSize) { type(b.getInt(classDefsOff + it * 32)) }
        val provDescs = HashSet<String>()
        for (i in 0 until classDefsSize) {
            val sup = b.getInt(classDefsOff + i * 32 + 8)
            if (sup != -1 && type(sup) == "Landroid/content/ContentProvider;") provDescs += names[i]
        }
        if (provDescs.isEmpty()) return
        provDescs.forEach { providers += it.removePrefix("L").removeSuffix(";").replace('/', '.') }
        val pkgs = provDescs.map { it.substringBeforeLast('/') }.toSet()

        // Pass 2: const-string operands in the provider, its nested classes and contract-like neighbours.
        for (i in 0 until classDefsSize) {
            val n = names[i]
            val outer = n.substringBefore('$').let { if (it.endsWith(";")) it else "$it;" }
            val simple = n.substringAfterLast('/')
            val wanted = n in provDescs || outer in provDescs || (n.substringBeforeLast('/') in pkgs && CONTRACT.containsMatchIn(simple))
            if (!wanted) continue
            val dataOff = b.getInt(classDefsOff + i * 32 + 24)
            if (dataOff == 0) continue
            for (codeOff in codeOffsets(dex, dataOff)) {
                for (idx in constStrings(b, codeOff)) {
                    if (idx in 0 until stringIdsSize && strings.size < MAX_STRINGS) strings += str(idx)
                }
            }
        }
    }

    private fun codeOffsets(dex: ByteArray, dataOff: Int): List<Int> {
        var pos = dataOff
        fun uleb(): Int {
            var r = 0; var sh = 0
            while (true) { val v = dex[pos++].toInt() and 0xff; r = r or ((v and 0x7f) shl sh); if (v and 0x80 == 0) return r; sh += 7 }
        }
        val sf = uleb(); val inf = uleb(); val dm = uleb(); val vm = uleb()
        repeat(sf + inf) { uleb(); uleb() }
        val out = ArrayList<Int>()
        repeat(dm + vm) { uleb(); uleb(); val c = uleb(); if (c != 0) out += c }
        return out
    }

    /** Walks one method's instructions with the Dalvik width table; returns const-string indices. */
    private fun constStrings(b: ByteBuffer, codeOff: Int): List<Int> {
        val n = b.getInt(codeOff + 12)
        val base = codeOff + 16
        val out = ArrayList<Int>()
        var pc = 0
        while (pc < n) {
            val unit = b.getShort(base + pc * 2).toInt() and 0xffff
            val op = unit and 0xff
            if (op == 0x1a) out += b.getShort(base + pc * 2 + 2).toInt() and 0xffff
            if (op == 0x1b) out += b.getInt(base + pc * 2 + 2)
            pc += when {
                unit == 0x0100 -> 4 + (b.getShort(base + pc * 2 + 2).toInt() and 0xffff) * 2
                unit == 0x0200 -> 2 + (b.getShort(base + pc * 2 + 2).toInt() and 0xffff) * 4
                unit == 0x0300 -> {
                    val w = b.getShort(base + pc * 2 + 2).toInt() and 0xffff
                    val size = b.getInt(base + pc * 2 + 4).toLong()
                    (4 + (size * w + 1) / 2).toInt()
                }
                else -> WIDTH[op]
            }
        }
        return out
    }

    private val WIDTH = IntArray(256) { op ->
        when (op) {
            0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29 -> 2
            0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c -> 3
            0x18 -> 5
            in 0x2d..0x3d -> 2
            in 0x44..0x6d -> 2
            in 0x6e..0x72, in 0x74..0x78 -> 3
            in 0x90..0xaf -> 2
            in 0xd0..0xe2 -> 2
            0xfa, 0xfb -> 4
            0xfc, 0xfd -> 3
            0xfe, 0xff -> 2
            else -> 1
        }
    }
}
