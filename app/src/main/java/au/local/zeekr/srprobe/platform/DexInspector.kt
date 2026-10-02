package au.local.zeekr.srprobe.platform

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * v0.3: member-level detail for a few named APKs (READ_ONLY_AUDIT.md section B).
 *
 * Reads dex name tables (class, superclass, interfaces, field and method names with their types) and the
 * binary AndroidManifest.xml element tree, as bytes. No ClassLoader, no DexFile, nothing is loaded or run,
 * and nothing found here is bound, started or called.
 */
object DexInspector {

    data class ClassDetail(
        val name: String,
        val superName: String?,
        val interfaces: List<String>,
        val fields: List<String>,
        val methods: List<String>
    )

    data class Result(val source: String, val path: String, val classes: List<ClassDetail>, val manifest: List<String>, val note: String?)

    private const val MAX_DEX_BYTES = 64L * 1024 * 1024
    private const val MAX_CONTAINER_BYTES = 96L * 1024 * 1024
    private val ANON = Regex("\\$\\d")

    /** Packages that hold SR / perception plumbing on the 7X (from the v0.2 car report). */
    val FOCUS_PREFIXES = listOf(
        "com.zeekr.sdk.adcu", "com.zeekr.sdk.drive", "com.zeekr.soa.adcu", "com.zeekr.autopilot.sr",
        "com.zeekr.vehicle.someip", "com.zeekr.sr", "com.zeekr.launcher.manager", "com.zeekr.vehicle.data"
    )
    private val FOCUS_WORDS = Regex("SRObject|SrService|SrStatus|Percep|Fusion|Obstacle|EgoCar|Adcu|ADCU")
    private val PLUMBING = Regex("(Service|Binder|Connect|Bind|Proxy|Manager|Provider|Stub)")

    fun wanted(name: String): Boolean {
        if (ANON.containsMatchIn(name) || name.contains("\$\$") || name.endsWith("\$Companion")) return false
        val simple = name.substringAfterLast('.')
        if (FOCUS_PREFIXES.any { name.startsWith(it) }) return true
        if (name.startsWith("com.zeekr.sdk.base") && PLUMBING.containsMatchIn(simple)) return true
        return (name.startsWith("com.zeekr") || name.startsWith("com.ecarx") || name.startsWith("com.geely")) && FOCUS_WORDS.containsMatchIn(simple)
    }

    private fun rank(c: ClassDetail): Int {
        val s = c.name.substringAfterLast('.')
        return when {
            s.contains("SRObject") -> 0
            FOCUS_WORDS.containsMatchIn(s) -> 1
            c.name.startsWith("com.zeekr.autopilot.sr") || c.name.startsWith("com.zeekr.sdk.adcu") || c.name.startsWith("com.zeekr.sdk.drive") -> 2
            else -> 3
        }
    }

    fun inspect(source: String, path: String, maxClasses: Int = 150): Result {
        val f = File(path)
        if (!f.canRead()) return Result(source, path, emptyList(), emptyList(), "not readable")
        val out = ArrayList<ClassDetail>()
        var manifest: List<String> = emptyList()
        val notes = ArrayList<String>()
        try {
            if (path.endsWith(".vdex") || path.endsWith(".odex")) {
                if (f.length() > MAX_CONTAINER_BYTES) return Result(source, path, emptyList(), emptyList(), "too large")
                val bytes = f.readBytes()
                val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
                var i = 0
                while (i + 0x70 <= bytes.size) {
                    if (bytes[i] == 'd'.code.toByte() && bytes[i + 1] == 'e'.code.toByte() && bytes[i + 2] == 'x'.code.toByte() && bytes[i + 3] == '\n'.code.toByte()) {
                        val size = b.getInt(i + 0x20)
                        if (size >= 0x70 && i.toLong() + size <= bytes.size) { parse(bytes.copyOfRange(i, i + size), out); i += size; continue }
                    }
                    i++
                }
            } else ZipFile(f).use { zip ->
                val e = zip.entries()
                while (e.hasMoreElements()) {
                    val z = e.nextElement()
                    if (Regex("classes\\d*\\.dex").matches(z.name) && z.size <= MAX_DEX_BYTES) parse(zip.getInputStream(z).use { it.readBytes() }, out)
                    if (z.name == "AndroidManifest.xml") manifest = runCatching { ManifestReader.components(zip.getInputStream(z).use { it.readBytes() }) }
                        .getOrElse { listOf("manifest parse failed: ${it.javaClass.simpleName}") }
                }
            }
        } catch (t: Throwable) {
            notes += "${t.javaClass.simpleName}: ${t.message}"
        }
        val sorted = out.distinctBy { it.name }.sortedWith(Comparator { a, b -> val r = rank(a) - rank(b); if (r != 0) r else a.name.compareTo(b.name) })
        if (sorted.size > maxClasses) notes += "${sorted.size - maxClasses} more matching classes not listed"
        return Result(source, path, sorted.take(maxClasses), manifest, notes.joinToString("; ").ifEmpty { null })
    }

    private fun parse(dex: ByteArray, out: MutableList<ClassDetail>) {
        if (dex.size < 0x70 || dex[0] != 'd'.code.toByte()) return
        val b = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsOff = b.getInt(0x3C)
        val typeIdsOff = b.getInt(0x44)
        val protoIdsOff = b.getInt(0x4C)
        val fieldIdsOff = b.getInt(0x54)
        val methodIdsOff = b.getInt(0x5C)
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
        fun typeDesc(idx: Int): String = str(b.getInt(typeIdsOff + idx * 4))
        fun pretty(desc: String): String {
            var d = desc; var dims = 0
            while (d.startsWith("[")) { dims++; d = d.substring(1) }
            val base = when (d) {
                "V" -> "void"; "Z" -> "boolean"; "B" -> "byte"; "S" -> "short"; "C" -> "char"
                "I" -> "int"; "J" -> "long"; "F" -> "float"; "D" -> "double"
                else -> d.removePrefix("L").removeSuffix(";").substringAfterLast('/')
            }
            return base + "[]".repeat(dims)
        }
        var pos = 0
        fun uleb(): Int {
            var result = 0; var shift = 0
            while (true) {
                val v = dex[pos++].toInt() and 0xff
                result = result or ((v and 0x7f) shl shift)
                if (v and 0x80 == 0) return result
                shift += 7
            }
        }
        fun typeList(off: Int): List<String> {
            if (off == 0) return emptyList()
            val n = b.getInt(off)
            return (0 until n).map { pretty(typeDesc(b.getShort(off + 4 + it * 2).toInt() and 0xffff)) }
        }

        for (i in 0 until classDefsSize) {
            val base = classDefsOff + i * 32
            val desc = typeDesc(b.getInt(base))
            if (!desc.startsWith("L")) continue
            val name = desc.substring(1, desc.length - 1).replace('/', '.')
            if (!wanted(name)) continue
            val superIdx = b.getInt(base + 8)
            val superName = if (superIdx == -1) null else typeDesc(superIdx).removePrefix("L").removeSuffix(";").replace('/', '.').takeIf { it != "java.lang.Object" }
            val interfaces = typeList(b.getInt(base + 12))
            val fields = ArrayList<String>()
            val methods = ArrayList<String>()
            val dataOff = b.getInt(base + 24)
            if (dataOff != 0) {
                pos = dataOff
                val sf = uleb(); val inf = uleb(); val dm = uleb(); val vm = uleb()
                var idx = 0
                for (k in 0 until sf + inf) {
                    if (k == sf) idx = 0
                    idx += uleb(); val flags = uleb()
                    val fo = fieldIdsOff + idx * 8
                    val ftype = pretty(typeDesc(b.getShort(fo + 2).toInt() and 0xffff))
                    if (fields.size < 60) fields += "${if (flags and 0x8 != 0) "static " else ""}$ftype ${str(b.getInt(fo + 4))}"
                }
                idx = 0
                for (k in 0 until dm + vm) {
                    if (k == dm) idx = 0
                    idx += uleb(); uleb(); uleb()
                    val mo = methodIdsOff + idx * 8
                    val mname = str(b.getInt(mo + 4))
                    if (mname == "<clinit>" || mname.startsWith("access$") || methods.size >= 60) continue
                    val po = protoIdsOff + (b.getShort(mo + 2).toInt() and 0xffff) * 12
                    methods += "${pretty(typeDesc(b.getInt(po + 4)))} $mname(${typeList(b.getInt(po + 8)).joinToString()})"
                }
            }
            out += ClassDetail(name, superName, interfaces, fields, methods)
        }
    }
}

/** Binary AndroidManifest.xml element walker: services, providers, receivers, permissions and their actions. */
object ManifestReader {

    private val KEEP = setOf("manifest", "permission", "uses-permission", "service", "provider", "receiver", "action", "uses-library")
    private val ATTRS = setOf("package", "name", "exported", "permission", "readPermission", "writePermission",
        "protectionLevel", "authorities", "enabled", "process", "sharedUserId")

    fun components(x: ByteArray): List<String> {
        val b = ByteBuffer.wrap(x).order(ByteOrder.LITTLE_ENDIAN)
        if (b.getShort(0).toInt() != 0x0003) return emptyList()
        var strings: List<String> = emptyList()
        val out = ArrayList<String>()
        var inActivity = false
        var pos = b.getShort(2).toInt() and 0xffff
        while (pos + 8 <= x.size && out.size < 300) {
            val type = b.getShort(pos).toInt() and 0xffff
            val size = b.getInt(pos + 4)
            if (size <= 0) break
            when (type) {
                0x0001 -> strings = pool(x, b, pos)
                0x0102 -> {
                    val name = strings.getOrNull(b.getInt(pos + 20)) ?: ""
                    val attrStart = b.getShort(pos + 24).toInt() and 0xffff
                    val attrSize = b.getShort(pos + 26).toInt() and 0xffff
                    val count = b.getShort(pos + 28).toInt() and 0xffff
                    if (name == "activity" || name == "activity-alias") inActivity = true
                    if (name in KEEP && !(inActivity && name == "action")) {
                        val attrs = (0 until count).mapNotNull { k ->
                            val a = pos + 16 + attrStart + k * attrSize
                            val an = strings.getOrNull(b.getInt(a + 4)) ?: return@mapNotNull null
                            if (an !in ATTRS) return@mapNotNull null
                            val raw = b.getInt(a + 8)
                            val dataType = x[a + 15].toInt() and 0xff
                            val data = b.getInt(a + 16)
                            val v = when {
                                raw != -1 -> strings.getOrNull(raw) ?: "?"
                                dataType == 0x12 -> (data != 0).toString()
                                else -> "0x" + Integer.toHexString(data)
                            }
                            "$an=$v"
                        }
                        val indent = if (name == "action") "    " else "  "
                        out += indent + name + " " + attrs.joinToString(" ")
                    }
                }
                0x0103 -> {
                    val name = strings.getOrNull(b.getInt(pos + 20)) ?: ""
                    if (name == "activity" || name == "activity-alias") inActivity = false
                }
            }
            pos += size
        }
        return out
    }

    fun pool(x: ByteArray, b: ByteBuffer, pos: Int): List<String> {
        val hdr = b.getShort(pos + 2).toInt() and 0xffff
        val count = b.getInt(pos + 8)
        val utf8 = b.getInt(pos + 16) and 0x100 != 0
        val base = pos + b.getInt(pos + 20)
        return (0 until minOf(count, 50000)).map { i ->
            runCatching {
                var p = base + b.getInt(pos + hdr + i * 4)
                if (utf8) {
                    p += if (x[p].toInt() and 0x80 != 0) 2 else 1
                    val b0 = x[p].toInt() and 0xff
                    val len = if (b0 and 0x80 != 0) { val l = ((b0 and 0x7f) shl 8) or (x[p + 1].toInt() and 0xff); p += 2; l } else { p += 1; b0 }
                    String(x, p, len, Charsets.UTF_8)
                } else {
                    var n = b.getShort(p).toInt() and 0xffff
                    if (n and 0x8000 != 0) { n = ((n and 0x7fff) shl 16) or (b.getShort(p + 2).toInt() and 0xffff); p += 4 } else p += 2
                    String(x, p, n * 2, Charsets.UTF_16LE)
                }
            }.getOrDefault("")
        }
    }
}
