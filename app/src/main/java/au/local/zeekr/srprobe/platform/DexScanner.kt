package au.local.zeekr.srprobe.platform

import au.local.zeekr.srprobe.model.DexScanRecord
import au.local.zeekr.srprobe.model.Terms
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Lists class names and string constants inside a jar/APK (or a .vdex next to it) by parsing dex bytes.
 *
 * This is pure file reading: no ClassLoader, no DexFile, no code from the scanned file is loaded or run.
 * It answers "does the head unit ship anything named like a perception/SR API?" even for classes that live
 * in other apps' APKs and are therefore not reachable by reflection.
 */
object DexScanner {

    private const val MAX_DEX_BYTES = 64L * 1024 * 1024
    private const val MAX_CONTAINER_BYTES = 96L * 1024 * 1024
    private const val MAX_ASSETS_PER_SOURCE = 150
    private const val MAX_VENDOR_CLASSES = 5000
    private const val MAX_PERCEPTION = 200
    private const val MAX_ENDPOINTS = 250
    private const val MAX_MANIFEST = 120

    /** Identifier-ish strings only: class/AIDL/proto names, property keys, topic names. */
    private val IDENT = Regex("^[A-Za-z0-9_.$/:\\-]{4,160}$")
    private val AIDL = Regex("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)+\\.I[A-Z][A-Za-z0-9_]*$")
    private val DEX_ENTRY = Regex("classes\\d*\\.dex")

    private class Acc(val light: Boolean) {
        val classes = LinkedHashSet<String>()
        val vendor = LinkedHashSet<String>()
        val strings = LinkedHashSet<String>()
        val perception = HashMap<String, Int>()
        val endpoints = LinkedHashSet<String>()
        val maxClasses = if (light) 300 else 3000
        val maxStrings = if (light) 150 else 600
    }

    /**
     * light = true for app APKs: smaller caps and no full vendor class list, so scanning hundreds of
     * APKs stays within memory.
     */
    fun scan(source: String, path: String, light: Boolean = false): DexScanRecord {
        val f = File(path)
        if (!f.canRead()) return DexScanRecord(source, path, 0, 0, emptyList(), emptyList(), emptyList(), emptyList(), "not readable by this app")
        val acc = Acc(light)
        val libs = LinkedHashSet<String>()
        val assets = ArrayList<String>()
        var manifest: List<String> = emptyList()
        var dexCount = 0
        var total = 0
        val notes = ArrayList<String>()
        try {
            ZipFile(f).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    val n = e.name
                    when {
                        DEX_ENTRY.matches(n) -> {
                            dexCount++
                            if (e.size > MAX_DEX_BYTES) { notes += "$n skipped (${e.size / 1048576} MB)"; continue }
                            val bytes = zip.getInputStream(e).use { it.readBytes() }
                            total += parse(bytes, acc)
                        }
                        n == "AndroidManifest.xml" -> manifest = runCatching {
                            manifestStrings(zip.getInputStream(e).use { it.readBytes() })
                        }.getOrElse { notes += "manifest unreadable"; emptyList() }
                        n.startsWith("lib/") && n.endsWith(".so") -> libs += n.substringAfterLast('/')
                        (n.startsWith("assets/") || n.startsWith("res/raw/")) && assets.size < MAX_ASSETS_PER_SOURCE &&
                            Terms.match(n, Terms.RENDER + Terms.STRONG).isNotEmpty() -> assets += n
                    }
                }
            }
        } catch (t: Throwable) {
            notes += "zip read failed: ${t.javaClass.simpleName}: ${t.message}"
        }
        if (dexCount == 0) notes += "no classes.dex inside (code may be pre-compiled/stripped)"
        return record(source, path, dexCount, total, acc, libs.sorted(), assets, notes, manifest)
    }

    /**
     * v0.2: a .vdex/.odex/.dex file read as bytes. Only embedded standard dex images ("dex\n0..") are parsed;
     * compact dex ("cdex") is counted and reported but not decoded.
     */
    fun scanContainer(source: String, path: String): DexScanRecord {
        val f = File(path)
        if (!f.canRead()) return DexScanRecord(source, path, 0, 0, emptyList(), emptyList(), emptyList(), emptyList(), "not readable by this app")
        if (f.length() > MAX_CONTAINER_BYTES) return DexScanRecord(source, path, 0, 0, emptyList(), emptyList(), emptyList(), emptyList(), "skipped (${f.length() / 1048576} MB)")
        val acc = Acc(light = true)
        val notes = ArrayList<String>()
        var dexCount = 0
        var total = 0
        var cdex = 0
        try {
            val bytes = f.readBytes()
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            var i = 0
            while (i + 0x70 <= bytes.size) {
                if (bytes[i] == 'd'.code.toByte() && bytes[i + 1] == 'e'.code.toByte() && bytes[i + 2] == 'x'.code.toByte() &&
                    bytes[i + 3] == '\n'.code.toByte() && bytes[i + 4] == '0'.code.toByte() && bytes[i + 7] == 0.toByte()) {
                    val size = b.getInt(i + 0x20)
                    if (size >= 0x70 && i.toLong() + size <= bytes.size) {
                        dexCount++
                        total += parse(bytes.copyOfRange(i, i + size), acc)
                        i += size
                        continue
                    }
                } else if (bytes[i] == 'c'.code.toByte() && bytes[i + 1] == 'd'.code.toByte() && bytes[i + 2] == 'e'.code.toByte() &&
                    bytes[i + 3] == 'x'.code.toByte() && bytes[i + 4] == '0'.code.toByte()) {
                    cdex++
                }
                i++
            }
        } catch (t: Throwable) {
            notes += "read failed: ${t.javaClass.simpleName}: ${t.message}"
        }
        if (cdex > 0) notes += "$cdex compact dex image(s) not decoded"
        if (dexCount == 0 && cdex == 0) notes += "no dex image inside"
        return record(source, path, dexCount, total, acc, emptyList(), emptyList(), notes, emptyList())
    }

    private fun record(source: String, path: String, dexCount: Int, total: Int, acc: Acc, libs: List<String>,
                       assets: List<String>, notes: List<String>, manifest: List<String>) = DexScanRecord(
        source, path, dexCount, total,
        acc.classes.take(acc.maxClasses), acc.strings.take(acc.maxStrings),
        libs, assets, notes.joinToString("; ").ifEmpty { null },
        if (acc.light) emptyList() else acc.vendor.take(MAX_VENDOR_CLASSES),
        acc.perception.entries.sortedByDescending { it.value }.take(MAX_PERCEPTION).map { "${it.value} ${it.key}" },
        acc.endpoints.take(MAX_ENDPOINTS),
        manifest
    )

    /** Returns the class count of this dex; adds relevant class names and strings to the accumulator. */
    private fun parse(dex: ByteArray, acc: Acc): Int {
        if (dex.size < 0x70 || dex[0] != 'd'.code.toByte() || dex[1] != 'e'.code.toByte() || dex[2] != 'x'.code.toByte()) return 0
        val b = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = b.getInt(0x38)
        val stringIdsOff = b.getInt(0x3C)
        val typeIdsOff = b.getInt(0x44)
        val classDefsSize = b.getInt(0x60)
        val classDefsOff = b.getInt(0x64)

        fun stringAt(idx: Int): String {
            var p = b.getInt(stringIdsOff + idx * 4)
            // Skip the ULEB128 UTF-16 length.
            while (dex[p].toInt() and 0x80 != 0) p++
            p++
            var end = p
            while (end < dex.size && dex[end].toInt() != 0) end++
            return String(dex, p, end - p, Charsets.UTF_8)
        }

        for (i in 0 until classDefsSize) {
            val classIdx = b.getInt(classDefsOff + i * 32)
            val descIdx = b.getInt(typeIdsOff + classIdx * 4)
            val desc = stringAt(descIdx)
            if (!desc.startsWith("L") || !desc.endsWith(";")) continue
            val name = desc.substring(1, desc.length - 1).replace('/', '.')
            if (Terms.isRelevantClass(name) && acc.classes.size < acc.maxClasses) acc.classes += name
            if (!acc.light && Terms.isVendor(name) && acc.vendor.size < MAX_VENDOR_CLASSES) acc.vendor += name
            if (!name.contains("$\$") && acc.perception.size < MAX_PERCEPTION * 4) {
                val score = Terms.perceptionScore(name)
                if (score >= 2) acc.perception[name] = score
            }
        }
        for (i in 0 until stringIdsSize) {
            if (acc.strings.size >= acc.maxStrings && acc.endpoints.size >= MAX_ENDPOINTS) break
            val s = stringAt(i)
            if (s.length < 4 || s.length > 160 || s.startsWith("L") && s.endsWith(";")) continue
            if (!IDENT.matches(s)) continue
            if (acc.endpoints.size < MAX_ENDPOINTS && isEndpoint(s)) acc.endpoints += s
            if (acc.strings.size < acc.maxStrings && Terms.match(s, Terms.STRONG).isNotEmpty()) acc.strings += s
        }
        return classDefsSize
    }

    /** Vendor AIDL descriptors, intent actions and content authorities: names a later version could look up. */
    private fun isEndpoint(s: String): Boolean {
        if (s.contains("au.local.zeekr")) return false // this app's own provider
        if (s.startsWith("content://")) return Terms.isVendor(s.removePrefix("content://")) || s.contains("zeekr") || s.contains("ecarx")
        if (!(Terms.isVendor(s) || s.startsWith("vendor."))) return false
        return AIDL.matches(s) || s.contains(".action.", ignoreCase = true) || s.contains(".ACTION_") || Terms.perceptionScore(s) >= 2
    }

    /** Vendor-namespace strings from a binary AndroidManifest.xml string pool (bytes only). */
    fun manifestStrings(x: ByteArray): List<String> {
        val b = ByteBuffer.wrap(x).order(ByteOrder.LITTLE_ENDIAN)
        if (x.size < 36 || b.getShort(0).toInt() != 0x0003) return emptyList()
        val pos = b.getShort(2).toInt() and 0xffff
        if (b.getShort(pos).toInt() != 0x0001) return emptyList()
        val hdr = b.getShort(pos + 2).toInt() and 0xffff
        val count = b.getInt(pos + 8)
        val utf8 = b.getInt(pos + 16) and 0x100 != 0
        val base = pos + b.getInt(pos + 20)
        val out = LinkedHashSet<String>()
        for (i in 0 until minOf(count, 20000)) {
            val s = runCatching {
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
            }.getOrNull() ?: continue
            if (IDENT.matches(s) && s.contains('.') && (Terms.isVendor(s) || s.startsWith("vendor."))) out += s
            if (out.size >= MAX_MANIFEST) break
        }
        return out.toList()
    }
}
