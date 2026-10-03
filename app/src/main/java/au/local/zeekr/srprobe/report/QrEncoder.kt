package au.local.zeekr.srprobe.report

/**
 * v0.8.1: minimal QR Code encoder (ISO/IEC 18004), byte mode, error-correction level M, versions 1-40.
 * Pure computation, no Android or network use: it turns report text into a grid of dark/light modules so the
 * owner's phone camera can read the report off the screen.
 */
object QrEncoder {

    private val ECC_PER_BLOCK_M = intArrayOf(-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
        26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28)
    private val BLOCKS_M = intArrayOf(-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14,
        16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49)

    /** Returns modules[y][x], true = dark. Throws if the data does not fit version 40-M. */
    fun encode(data: ByteArray): Array<BooleanArray> {
        var ver = 1
        while (true) {
            val ccBits = if (ver <= 9) 8 else 16
            if (4 + ccBits + data.size * 8 <= dataCodewords(ver) * 8) break
            ver++
            require(ver <= 40) { "data too long for one QR code" }
        }
        val cap = dataCodewords(ver) * 8
        val bits = ArrayList<Boolean>()
        fun put(v: Int, n: Int) { for (i in n - 1 downTo 0) bits += (v ushr i) and 1 != 0 }
        put(4, 4)
        put(data.size, if (ver <= 9) 8 else 16)
        for (b in data) put(b.toInt() and 0xff, 8)
        put(0, minOf(4, cap - bits.size))
        put(0, (8 - bits.size % 8) % 8)
        var pad = 0xEC
        while (bits.size < cap) { put(pad, 8); pad = pad xor 0xEC xor 0x11 }
        val codewords = ByteArray(bits.size / 8) { i -> var v = 0; for (k in 0 until 8) if (bits[i * 8 + k]) v = v or (0x80 ushr k); v.toByte() }
        return Grid(ver).build(addEcc(codewords, ver))
    }

    private fun rawModules(ver: Int): Int {
        var r = (16 * ver + 128) * ver + 64
        if (ver >= 2) { val n = ver / 7 + 2; r -= (25 * n - 10) * n - 55; if (ver >= 7) r -= 36 }
        return r
    }

    private fun dataCodewords(ver: Int) = rawModules(ver) / 8 - ECC_PER_BLOCK_M[ver] * BLOCKS_M[ver]

    private fun addEcc(data: ByteArray, ver: Int): ByteArray {
        val numBlocks = BLOCKS_M[ver]
        val eccLen = ECC_PER_BLOCK_M[ver]
        val raw = rawModules(ver) / 8
        val numShort = numBlocks - raw % numBlocks
        val shortLen = raw / numBlocks
        val div = rsDivisor(eccLen)
        val blocks = ArrayList<ByteArray>()
        var k = 0
        for (i in 0 until numBlocks) {
            val datLen = shortLen - eccLen + (if (i < numShort) 0 else 1)
            val dat = data.copyOfRange(k, k + datLen); k += datLen
            val ecc = rsRemainder(dat, div)
            val block = ByteArray(shortLen + 1)
            System.arraycopy(dat, 0, block, 0, datLen)
            System.arraycopy(ecc, 0, block, block.size - eccLen, eccLen)
            blocks += block
        }
        val out = ArrayList<Byte>()
        for (i in 0 until blocks[0].size) for (j in blocks.indices) {
            if (i != shortLen - eccLen || j >= numShort) out += blocks[j][i]
        }
        return out.toByteArray()
    }

    private fun mul(x: Int, y: Int): Int {
        var z = 0
        for (i in 7 downTo 0) { z = (z shl 1) xor ((z ushr 7) * 0x11D); z = z xor (((y ushr i) and 1) * x) }
        return z
    }

    private fun rsDivisor(degree: Int): IntArray {
        val r = IntArray(degree); r[degree - 1] = 1
        var root = 1
        for (i in 0 until degree) {
            for (j in 0 until degree) { r[j] = mul(r[j], root); if (j + 1 < degree) r[j] = r[j] xor r[j + 1] }
            root = mul(root, 2)
        }
        return r
    }

    private fun rsRemainder(data: ByteArray, div: IntArray): ByteArray {
        val r = IntArray(div.size)
        for (b in data) {
            val f = (b.toInt() and 0xff) xor r[0]
            System.arraycopy(r, 1, r, 0, r.size - 1); r[r.size - 1] = 0
            for (i in r.indices) r[i] = r[i] xor mul(div[i], f)
        }
        return ByteArray(r.size) { r[it].toByte() }
    }

    private class Grid(val ver: Int) {
        val size = ver * 4 + 17
        val m = Array(size) { BooleanArray(size) }
        val fn = Array(size) { BooleanArray(size) }
        fun set(x: Int, y: Int, dark: Boolean) { m[y][x] = dark; fn[y][x] = true }

        fun build(cw: ByteArray): Array<BooleanArray> {
            for (i in 0 until size) { set(6, i, i % 2 == 0); set(i, 6, i % 2 == 0) }
            finder(3, 3); finder(size - 4, 3); finder(3, size - 4)
            val al = alignPositions()
            for (i in al.indices) for (j in al.indices) {
                if (i == 0 && j == 0 || i == 0 && j == al.size - 1 || i == al.size - 1 && j == 0) continue
                for (dy in -2..2) for (dx in -2..2) set(al[i] + dx, al[j] + dy, maxOf(Math.abs(dx), Math.abs(dy)) != 1)
            }
            format(0)
            version()
            place(cw)
            var best = 0; var bestScore = Int.MAX_VALUE
            for (mask in 0 until 8) {
                applyMask(mask); format(mask)
                val p = penalty()
                if (p < bestScore) { best = mask; bestScore = p }
                applyMask(mask)
            }
            applyMask(best); format(best)
            return m
        }

        fun finder(cx: Int, cy: Int) {
            for (dy in -4..4) for (dx in -4..4) {
                val x = cx + dx; val y = cy + dy
                if (x in 0 until size && y in 0 until size) {
                    val d = maxOf(Math.abs(dx), Math.abs(dy)); set(x, y, d != 2 && d != 4)
                }
            }
        }

        fun alignPositions(): IntArray {
            if (ver == 1) return IntArray(0)
            val n = ver / 7 + 2
            val step = (ver * 8 + n * 3 + 5) / (n * 4 - 4) * 2
            val r = IntArray(n); r[0] = 6
            var pos = size - 7
            for (i in n - 1 downTo 1) { r[i] = pos; pos -= step }
            return r
        }

        fun format(mask: Int) {
            val data = (0 shl 3) or mask // level M = 0b00
            var rem = data
            repeat(10) { rem = (rem shl 1) xor ((rem ushr 9) * 0x537) }
            val bits = ((data shl 10) or rem) xor 0x5412
            fun bit(i: Int) = (bits ushr i) and 1 != 0
            for (i in 0..5) set(8, i, bit(i))
            set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8))
            for (i in 9 until 15) set(14 - i, 8, bit(i))
            for (i in 0 until 8) set(size - 1 - i, 8, bit(i))
            for (i in 8 until 15) set(8, size - 15 + i, bit(i))
            set(8, size - 8, true)
        }

        fun version() {
            if (ver < 7) return
            var rem = ver
            repeat(12) { rem = (rem shl 1) xor ((rem ushr 11) * 0x1F25) }
            val bits = (ver shl 12) or rem
            for (i in 0 until 18) {
                val b = (bits ushr i) and 1 != 0
                val a = size - 11 + i % 3; val c = i / 3
                set(a, c, b); set(c, a, b)
            }
        }

        fun place(cw: ByteArray) {
            var i = 0
            var right = size - 1
            while (right >= 1) {
                if (right == 6) right = 5
                for (vert in 0 until size) for (j in 0..1) {
                    val x = right - j
                    val upward = ((right + 1) and 2) == 0
                    val y = if (upward) size - 1 - vert else vert
                    if (!fn[y][x] && i < cw.size * 8) {
                        m[y][x] = ((cw[i ushr 3].toInt() ushr (7 - (i and 7))) and 1) != 0
                        i++
                    }
                }
                right -= 2
            }
        }

        fun applyMask(mask: Int) {
            for (y in 0 until size) for (x in 0 until size) {
                if (fn[y][x]) continue
                val inv = when (mask) {
                    0 -> (x + y) % 2 == 0; 1 -> y % 2 == 0; 2 -> x % 3 == 0; 3 -> (x + y) % 3 == 0
                    4 -> (x / 3 + y / 2) % 2 == 0; 5 -> x * y % 2 + x * y % 3 == 0
                    6 -> (x * y % 2 + x * y % 3) % 2 == 0; else -> ((x + y) % 2 + x * y % 3) % 2 == 0
                }
                if (inv) m[y][x] = !m[y][x]
            }
        }

        /** Simplified penalty (runs, 2x2 blocks, balance); any mask is valid, this just picks a cleaner one. */
        fun penalty(): Int {
            var p = 0
            for (y in 0 until size) {
                var run = 1
                for (x in 1 until size) { if (m[y][x] == m[y][x - 1]) { run++; if (run == 5) p += 3 else if (run > 5) p++ } else run = 1 }
            }
            for (x in 0 until size) {
                var run = 1
                for (y in 1 until size) { if (m[y][x] == m[y - 1][x]) { run++; if (run == 5) p += 3 else if (run > 5) p++ } else run = 1 }
            }
            for (y in 0 until size - 1) for (x in 0 until size - 1) {
                val c = m[y][x]; if (c == m[y][x + 1] && c == m[y + 1][x] && c == m[y + 1][x + 1]) p += 3
            }
            val dark = m.sumOf { r -> r.count { it } }
            val total = size * size
            p += (Math.abs(dark * 20 - total * 10) + total - 1) / total * 10
            return p
        }
    }

    /** Splits text into chunks (by characters, at most [maxBytes] UTF-8 bytes each) with an "SRP i/n" header. */
    fun chunks(text: String, maxBytes: Int = 700): List<String> {
        val parts = ArrayList<String>()
        var cur = StringBuilder(); var bytes = 0
        for (ch in text) {
            val b = ch.toString().toByteArray(Charsets.UTF_8).size
            if (bytes + b > maxBytes) { parts += cur.toString(); cur = StringBuilder(); bytes = 0 }
            cur.append(ch); bytes += b
        }
        if (cur.isNotEmpty()) parts += cur.toString()
        return parts.mapIndexed { i, s -> "SRP ${i + 1}/${parts.size}\n$s" }
    }
}
