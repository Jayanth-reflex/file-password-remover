package dev.jayanth.fpr

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Crypto {

    /**
     * PBKDF2-HMAC-SHA1, written out rather than taken from the JCE.
     *
     * `PBKDF2WithHmacSHA1` takes a char[] and the mapping from characters to
     * bytes has varied between providers; WinZip AES is defined over the raw
     * password bytes, so the derivation is done explicitly here.
     */
    fun pbkdf2Sha1(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(password, "HmacSHA1"))
        val output = ByteArray(length)
        var written = 0
        var block = 1
        while (written < length) {
            mac.update(salt)
            mac.update(byteArrayOf(
                ((block shr 24) and 0xFF).toByte(), ((block shr 16) and 0xFF).toByte(),
                ((block shr 8) and 0xFF).toByte(), (block and 0xFF).toByte(),
            ))
            var current = mac.doFinal()
            val accumulator = current.copyOf()
            repeat(iterations - 1) {
                current = mac.doFinal(current)
                for (index in accumulator.indices) accumulator[index] =
                    (accumulator[index].toInt() xor current[index].toInt()).toByte()
            }
            val take = minOf(accumulator.size, length - written)
            System.arraycopy(accumulator, 0, output, written, take)
            written += take
            block += 1
        }
        return output
    }

    /**
     * WinZip AES counter mode: a 128-bit **little-endian** counter starting at 1.
     *
     * That is where it differs from NIST CTR, which is why the keystream is
     * built explicitly instead of using "AES/CTR".
     */
    fun winZipAesCrypt(input: ByteArray, key: ByteArray): ByteArray {
        val blocks = (input.size + 15) / 16
        val counters = ByteArray(maxOf(blocks, 1) * 16)
        for (index in 1..maxOf(blocks, 1)) {
            var counter = index.toLong()
            val base = (index - 1) * 16
            for (position in 0 until 8) {
                counters[base + position] = (counter and 0xFF).toByte()
                counter = counter shr 8
            }
        }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val keystream = cipher.doFinal(counters)
        return ByteArray(input.size) { (input[it].toInt() xor keystream[it].toInt()).toByte() }
    }

    fun hmacSha1(message: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(message)
    }

    /** AES-CBC with no padding: [MS-OFFCRYPTO] zero-pads, it does not use PKCS#7. */
    fun aesCbcDecrypt(input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        if (input.size % 16 != 0) {
            throw FprException.CorruptFile("AES-CBC input is not a whole number of blocks")
        }
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)

    /** Constant-time comparison, so a wrong password cannot be narrowed by timing. */
    fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        for (index in left.indices) difference = difference or (left[index].toInt() xor right[index].toInt())
        return difference == 0
    }
}

fun sha256Hex(data: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

/**
 * Legacy PKWARE ZipCrypto.
 *
 * Weak by modern standards, and still common. This decrypts with a password the
 * user supplies; the known-plaintext weakness of the cipher is deliberately not
 * used, because attacking the cipher is exactly what this tool does not do.
 */
class ZipCryptoStream(password: ByteArray) {
    private var key0 = 0x12345678
    private var key1 = 0x23456789
    private var key2 = 0x34567890

    init {
        for (byte in password) updateKeys(byte.toInt() and 0xFF)
    }

    private fun updateKeys(byte: Int) {
        key0 = crc32Update(key0, byte)
        key1 += key0 and 0xFF
        key1 = key1 * 134775813 + 1
        key2 = crc32Update(key2, (key1 ushr 24) and 0xFF)
    }

    private fun decryptByte(): Int {
        // The product is taken at full width before the shift; truncating to 16
        // bits first drops the bits that end up in the output byte.
        val temp = (key2 or 2) and 0xFFFF
        return ((temp * (temp xor 1)) ushr 8) and 0xFF
    }

    fun decrypt(input: ByteArray): ByteArray = ByteArray(input.size) { index ->
        val plain = (input[index].toInt() xor decryptByte()) and 0xFF
        updateKeys(plain)
        plain.toByte()
    }

    private fun crc32Update(crc: Int, byte: Int): Int =
        (crc ushr 8) xor CRC_TABLE[(crc xor byte) and 0xFF]

    companion object {
        private val CRC_TABLE = IntArray(256) { index ->
            var value = index
            repeat(8) { value = if (value and 1 == 1) (value ushr 1) xor -306674912 else value ushr 1 }
            value
        }
    }
}
