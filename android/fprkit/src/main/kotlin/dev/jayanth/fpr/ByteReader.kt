package dev.jayanth.fpr

/**
 * Bounds-checked little-endian reader.
 *
 * Archive headers are attacker-controlled input, so a short or malformed buffer
 * becomes a [FprException.CorruptFile] rather than an index-out-of-bounds.
 */
class ByteReader(private val data: ByteArray, var offset: Int = 0) {

    val remaining: Int get() = data.size - offset

    fun seek(to: Int) {
        if (to < 0 || to > data.size) {
            throw FprException.CorruptFile("offset $to is outside a file of ${data.size} bytes")
        }
        offset = to
    }

    fun bytes(count: Int): ByteArray {
        if (count < 0 || remaining < count) {
            throw FprException.CorruptFile("wanted $count bytes, $remaining left")
        }
        return data.copyOfRange(offset, offset + count).also { offset += count }
    }

    fun u8(): Int = bytes(1)[0].toInt() and 0xFF

    fun u16(): Int {
        val b = bytes(2)
        return (b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8)
    }

    fun u32(): Long {
        val b = bytes(4)
        var value = 0L
        for (index in 3 downTo 0) value = (value shl 8) or (b[index].toLong() and 0xFF)
        return value
    }

    fun u64(): Long {
        val low = u32()
        val high = u32()
        return (high shl 32) or low
    }
}

/**
 * Last offset at which [signature] occurs, searching back from the end. The
 * end-of-central-directory record is variable length because of its trailing
 * comment, so it has to be found this way.
 */
fun ByteArray.lastIndexOfSignature(signature: Long, searchLimit: Int = 66_000): Int? {
    if (size < 4) return null
    val wanted = ByteArray(4) { ((signature shr (it * 8)) and 0xFF).toByte() }
    val lowest = maxOf(0, size - searchLimit)
    for (index in size - 4 downTo lowest) {
        if (this[index] == wanted[0] && this[index + 1] == wanted[1] &&
            this[index + 2] == wanted[2] && this[index + 3] == wanted[3]
        ) {
            return index
        }
    }
    return null
}

fun ByteArray.putU16(offset: Int, value: Int) {
    this[offset] = (value and 0xFF).toByte()
    this[offset + 1] = ((value shr 8) and 0xFF).toByte()
}
