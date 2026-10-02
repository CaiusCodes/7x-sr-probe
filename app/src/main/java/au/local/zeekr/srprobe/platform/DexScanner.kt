package au.local.zeekr.srprobe.platform

import au.local.zeekr.srprobe.model.DexScanRecord
import au.local.zeekr.srprobe.model.Terms
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Lists class names and string constants inside a jar/APK by parsing its classes*.dex as bytes.
 *
 * This is pure file reading: no ClassLoader, no DexFile, no code from the scanned file is loaded or run.
 * It answers "does the head unit ship anything named like a perception/SR API?" even for classes that live
 * in other apps' APKs and are therefore not reachable by reflection.
 */
object DexScanner {

    private const val MAX_DEX_BYTES = 64L * 1024 * 1024
    private const val MAX_CLASSES_PER_SOURCE = 3000
    private const val MAX_STRINGS_PER_SOURCE = 600
    private const val MAX_ASSETS_PER_SOURCE = 150
    private const val MAX_VENDOR_CLASSES = 5000

    /** Identifier-ish strings only: class/AIDL/proto names, property keys, topic names. */
    private val IDENT = Regex("^[A-Za-z0-9_.$/:\\-]{4,160}$")

    fun scan(source: String, path: String): DexScanRecord {
        val f = File(path)
        if (!f.canRead()) return DexScanRecord(source, path, 0, 0, emptyList(), emptyList(), emptyList(), emptyList(), "not readable by this app")
        val classes = LinkedHashSet<String>()
        val vendor = LinkedHashSet<String>()
        val strings = LinkedHashSet<String>()
        val libs = LinkedHashSet<String>()
        val assets = ArrayList<String>()
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
                        n.matches(Regex("classes\\d*\\.dex")) -> {
                            dexCount++
                            if (e.size > MAX_DEX_BYTES) { notes += "$n skipped (${e.size / 1048576} MB)"; continue }
                            val bytes = zip.getInputStream(e).use { it.readBytes() }
                            total += parse(bytes, classes, strings, vendor)
                        }
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
        return DexScanRecord(
            source, path, dexCount, total,
            classes.take(MAX_CLASSES_PER_SOURCE), strings.take(MAX_STRINGS_PER_SOURCE),
            libs.sorted(), assets, notes.joinToString("; ").ifEmpty { null }, vendor.take(MAX_VENDOR_CLASSES)
        )
    }

    /** Returns the class count of this dex; adds relevant class names and strings to the sets. */
    private fun parse(dex: ByteArray, classesOut: MutableSet<String>, stringsOut: MutableSet<String>, vendorOut: MutableSet<String>): Int {
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
            if (Terms.isRelevantClass(name)) classesOut += name
            if (Terms.isVendor(name) && vendorOut.size < MAX_VENDOR_CLASSES) vendorOut += name
        }
        if (stringsOut.size < MAX_STRINGS_PER_SOURCE) {
            for (i in 0 until stringIdsSize) {
                val s = stringAt(i)
                if (s.length < 4 || s.length > 160 || s.startsWith("L") && s.endsWith(";")) continue
                if (!IDENT.matches(s)) continue
                if (Terms.match(s, Terms.STRONG).isEmpty()) continue
                stringsOut += s
                if (stringsOut.size >= MAX_STRINGS_PER_SOURCE) break
            }
        }
        return classDefsSize
    }
}
