package dev.jayanth.fpr

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.Inflater

/** WinZip AE-x parameters, from the 0x9901 extra field. */
data class AesExtraField(
    val vendorVersion: Int,  // 1 = AE-1 (CRC kept), 2 = AE-2 (CRC zeroed)
    val strength: Int,       // 1 = 128, 2 = 192, 3 = 256
    val actualMethod: Int,   // the real compression method, hidden behind method 99
) {
    val keyBits: Int get() = when (strength) {
        1 -> 128
        2 -> 192
        else -> 256
    }

    /** Salt length is half the key length, per the WinZip AE specification. */
    val saltLength: Int get() = keyBits / 16
}

data class ZipEntry(
    val name: String,
    val flags: Int,
    val method: Int,
    val modTime: Int,
    val modDate: Int,
    val crc: Long,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val localHeaderOffset: Long,
    val extra: ByteArray,
    val comment: ByteArray,
    val versionMadeBy: Int,
    val internalAttributes: Int,
    val externalAttributes: Long,
) {
    val isEncrypted: Boolean get() = flags and 0x1 != 0
    val usesStrongEncryption: Boolean get() = flags and 0x40 != 0
    val aes: AesExtraField? get() = parseAes(extra)

    /** For AES entries the visible method is 99; the real one is in the extra field. */
    val effectiveMethod: Int get() = aes?.actualMethod ?: method

    companion object {
        fun parseAes(extra: ByteArray): AesExtraField? {
            val reader = ByteReader(extra)
            while (reader.remaining >= 4) {
                val headerId = runCatching { reader.u16() }.getOrNull() ?: return null
                val size = runCatching { reader.u16() }.getOrNull() ?: return null
                val payload = runCatching { reader.bytes(size) }.getOrNull() ?: return null
                if (headerId != 0x9901 || payload.size < 7) continue
                val field = ByteReader(payload)
                val vendorVersion = field.u16()
                val vendorId = field.bytes(2)
                val strength = field.u8()
                val actualMethod = field.u16()
                if (vendorId[0] != 'A'.code.toByte() || vendorId[1] != 'E'.code.toByte()) continue
                return AesExtraField(vendorVersion, strength, actualMethod)
            }
            return null
        }
    }
}

/** A decrypted entry, ready to be written back out. */
data class DecryptedEntry(
    val entry: ZipEntry,
    /** The compressed stream, decrypted but deliberately not recompressed. */
    val compressed: ByteArray,
    val plaintextSize: Int,
    val crc: Long,
    val method: Int,
)

/** An entry rewritten with encryption, ready to be assembled into an archive. */
data class ProtectedEntry(
    val entry: ZipEntry,
    val payload: ByteArray,
    val plaintextSize: Int,
    val isDirectory: Boolean,
)

object ZipArchive {
    const val CENTRAL_SIGNATURE = 0x02014B50L
    const val EOCD_SIGNATURE = 0x06054B50L
    const val LOCAL_SIGNATURE = 0x04034B50L
    private const val EOCD64_LOCATOR_SIGNATURE = 0x07064B50L
    private const val EOCD64_SIGNATURE = 0x06064B50L

    /**
     * Parse the central directory, which is the authoritative entry list: local
     * headers can lie, and for streamed archives they routinely do.
     */
    fun readCentralDirectory(data: ByteArray): List<ZipEntry> {
        val eocd = data.lastIndexOfSignature(EOCD_SIGNATURE)
            ?: throw FprException.CorruptFile(
                "no end-of-central-directory record: this is not a ZIP file"
            )
        val header = ByteReader(data, eocd + 4)
        header.u16(); header.u16(); header.u16()
        var entryCount = header.u16().toLong()
        header.u32()
        var centralOffset = header.u32()

        if (centralOffset == 0xFFFFFFFFL || entryCount == 0xFFFFL) {
            val zip64 = readZip64(data)
            entryCount = zip64.first
            centralOffset = zip64.second
        }

        val entries = ArrayList<ZipEntry>(entryCount.toInt().coerceAtMost(1 shl 16))
        val cursor = ByteReader(data)
        cursor.seek(centralOffset.toInt())
        repeat(entryCount.toInt()) {
            if (cursor.u32() != CENTRAL_SIGNATURE) {
                throw FprException.CorruptFile("central directory is truncated or misaligned")
            }
            val versionMadeBy = cursor.u16()
            cursor.u16()
            val flags = cursor.u16()
            val method = cursor.u16()
            val modTime = cursor.u16()
            val modDate = cursor.u16()
            val crc = cursor.u32()
            var compressedSize = cursor.u32()
            var uncompressedSize = cursor.u32()
            val nameLength = cursor.u16()
            val extraLength = cursor.u16()
            val commentLength = cursor.u16()
            cursor.u16()
            val internalAttributes = cursor.u16()
            val externalAttributes = cursor.u32()
            var localHeaderOffset = cursor.u32()
            val name = String(cursor.bytes(nameLength), Charsets.UTF_8)
            val extra = cursor.bytes(extraLength)
            val comment = cursor.bytes(commentLength)

            // Zip64 sizes live in the 0x0001 extra field when the 32-bit fields
            // are saturated.
            if (compressedSize == 0xFFFFFFFFL || uncompressedSize == 0xFFFFFFFFL ||
                localHeaderOffset == 0xFFFFFFFFL
            ) {
                val field = ByteReader(extra)
                while (field.remaining >= 4) {
                    val headerId = field.u16()
                    val size = field.u16()
                    val payload = field.bytes(size)
                    if (headerId != 0x0001) continue
                    val values = ByteReader(payload)
                    if (uncompressedSize == 0xFFFFFFFFL && values.remaining >= 8) uncompressedSize = values.u64()
                    if (compressedSize == 0xFFFFFFFFL && values.remaining >= 8) compressedSize = values.u64()
                    if (localHeaderOffset == 0xFFFFFFFFL && values.remaining >= 8) localHeaderOffset = values.u64()
                    break
                }
            }

            entries.add(
                ZipEntry(
                    name, flags, method, modTime, modDate, crc, compressedSize, uncompressedSize,
                    localHeaderOffset, extra, comment, versionMadeBy, internalAttributes,
                    externalAttributes,
                )
            )
        }
        return entries
    }

    private fun readZip64(data: ByteArray): Pair<Long, Long> {
        val locator = data.lastIndexOfSignature(EOCD64_LOCATOR_SIGNATURE)
            ?: throw FprException.CorruptFile("Zip64 sizes present but no Zip64 locator")
        val reader = ByteReader(data, locator + 4)
        reader.u32()
        val recordOffset = reader.u64()
        val record = ByteReader(data)
        record.seek(recordOffset.toInt())
        if (record.u32() != EOCD64_SIGNATURE) {
            throw FprException.CorruptFile("Zip64 end-of-central-directory record is missing")
        }
        record.u64(); record.u16(); record.u16(); record.u32(); record.u32(); record.u64()
        val entryCount = record.u64()
        record.u64()
        return entryCount to record.u64()
    }

    /** Where an entry's payload starts, per its local header. */
    fun payloadOffset(data: ByteArray, entry: ZipEntry): Int {
        val reader = ByteReader(data)
        reader.seek(entry.localHeaderOffset.toInt())
        if (reader.u32() != LOCAL_SIGNATURE) {
            throw FprException.CorruptFile("bad local header for ${entry.name}")
        }
        reader.seek(entry.localHeaderOffset.toInt() + 26)
        val nameLength = reader.u16()
        val extraLength = reader.u16()
        return entry.localHeaderOffset.toInt() + 30 + nameLength + extraLength
    }

    fun payload(data: ByteArray, entry: ZipEntry): ByteArray {
        val start = payloadOffset(data, entry)
        val end = start + entry.compressedSize.toInt()
        if (end > data.size) {
            throw FprException.CorruptFile("payload of ${entry.name} runs past the end of the file")
        }
        return data.copyOfRange(start, end)
    }

    fun decompress(payload: ByteArray, method: Int, expectedSize: Int): ByteArray = when (method) {
        0 -> payload
        8 -> inflate(payload, expectedSize)
        else -> throw FprException.UnsupportedFormat("compression method $method is not supported")
    }

    private fun inflate(input: ByteArray, expectedSize: Int): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        val inflater = Inflater(true)
        return try {
            inflater.setInput(input)
            val output = ByteArrayOutputStream(maxOf(expectedSize, input.size))
            val buffer = ByteArray(1 shl 16)
            while (!inflater.finished()) {
                val produced = inflater.inflate(buffer)
                if (produced == 0 && (inflater.needsInput() || inflater.needsDictionary())) break
                output.write(buffer, 0, produced)
            }
            output.toByteArray()
        } catch (error: java.util.zip.DataFormatException) {
            throw FprException.CorruptFile("DEFLATE stream did not decompress: ${error.message}")
        } finally {
            inflater.end()
        }
    }

    /**
     * Read every member's plaintext. Used by tests and by verification: the
     * output is re-read before success is reported.
     */
    fun readMembers(data: ByteArray): Map<String, ByteArray> {
        val members = LinkedHashMap<String, ByteArray>()
        for (entry in readCentralDirectory(data)) {
            if (entry.name.endsWith("/")) continue
            if (entry.isEncrypted) {
                throw FprException.InternalError("entry ${entry.name} is still encrypted")
            }
            members[entry.name] =
                decompress(payload(data, entry), entry.method, entry.uncompressedSize.toInt())
        }
        return members
    }

    /**
     * Rebuild an archive from already-decrypted entries.
     *
     * Compressed streams are written through untouched: nothing is recompressed,
     * so the content is preserved exactly.
     */
    fun write(entries: List<DecryptedEntry>): ByteArray {
        val output = ByteArrayOutputStream()
        val central = ByteArrayOutputStream()
        var offset = 0

        for (item in entries) {
            val name = item.entry.name.toByteArray(Charsets.UTF_8)
            // Clear the encryption bit, the data-descriptor bit (sizes are known
            // here, so a descriptor would be a lie) and the strong-encryption bit.
            val flags = item.entry.flags and 0x1.inv() and 0x8.inv() and 0x40.inv()
            val extra = strippedExtra(item.entry.extra)

            val local = ByteArrayOutputStream()
            local.u32(LOCAL_SIGNATURE); local.u16(20); local.u16(flags); local.u16(item.method)
            local.u16(item.entry.modTime); local.u16(item.entry.modDate)
            local.u32(item.crc); local.u32(item.compressed.size.toLong())
            local.u32(item.plaintextSize.toLong()); local.u16(name.size); local.u16(extra.size)
            local.write(name); local.write(extra); local.write(item.compressed)
            val localBytes = local.toByteArray()

            central.u32(CENTRAL_SIGNATURE); central.u16(item.entry.versionMadeBy); central.u16(20)
            central.u16(flags); central.u16(item.method)
            central.u16(item.entry.modTime); central.u16(item.entry.modDate)
            central.u32(item.crc); central.u32(item.compressed.size.toLong())
            central.u32(item.plaintextSize.toLong()); central.u16(name.size); central.u16(extra.size)
            central.u16(item.entry.comment.size); central.u16(0)
            central.u16(item.entry.internalAttributes); central.u32(item.entry.externalAttributes)
            central.u32(offset.toLong())
            central.write(name); central.write(extra); central.write(item.entry.comment)

            output.write(localBytes)
            offset += localBytes.size
        }

        val centralBytes = central.toByteArray()
        output.write(centralBytes)
        output.u32(EOCD_SIGNATURE); output.u16(0); output.u16(0)
        output.u16(entries.size); output.u16(entries.size)
        output.u32(centralBytes.size.toLong()); output.u32(offset.toLong()); output.u16(0)
        return output.toByteArray()
    }

    /** Drop the WinZip AES extra field: it would describe encryption that is gone. */
    private fun strippedExtra(extra: ByteArray): ByteArray {
        val reader = ByteReader(extra)
        val kept = ByteArrayOutputStream()
        while (reader.remaining >= 4) {
            val headerId = runCatching { reader.u16() }.getOrNull() ?: break
            val size = runCatching { reader.u16() }.getOrNull() ?: break
            val payload = runCatching { reader.bytes(size) }.getOrNull() ?: break
            if (headerId == 0x9901) continue
            kept.u16(headerId); kept.u16(payload.size); kept.write(payload)
        }
        return kept.toByteArray()
    }

    fun deflate(input: ByteArray): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true)
        return try {
            deflater.setInput(input)
            deflater.finish()
            val output = ByteArrayOutputStream(input.size)
            val buffer = ByteArray(1 shl 16)
            while (!deflater.finished()) {
                output.write(buffer, 0, deflater.deflate(buffer))
            }
            output.toByteArray()
        } finally {
            deflater.end()
        }
    }

    /**
     * Assemble an archive whose entries are WinZip AES-256.
     *
     * The stored compression method becomes 99 ("see the AES extra field") and
     * the real method moves into that field. The CRC is written as zero: AE-2
     * leaves integrity to the authentication code, and a CRC would hand anyone
     * without the password a check on the plaintext.
     */
    fun writeProtected(entries: List<ProtectedEntry>): ByteArray {
        val output = ByteArrayOutputStream()
        val central = ByteArrayOutputStream()
        var offset = 0

        for (item in entries) {
            val name = item.entry.name.toByteArray(Charsets.UTF_8)
            val extra = if (item.isDirectory) ByteArray(0) else aesExtraField(8)
            val flags = if (item.isDirectory) 0 else 0x1
            val method = if (item.isDirectory) 0 else 99

            val local = ByteArrayOutputStream()
            local.u32(LOCAL_SIGNATURE); local.u16(20); local.u16(flags); local.u16(method)
            local.u16(item.entry.modTime); local.u16(item.entry.modDate)
            local.u32(0); local.u32(item.payload.size.toLong())
            local.u32(item.plaintextSize.toLong()); local.u16(name.size); local.u16(extra.size)
            local.write(name); local.write(extra); local.write(item.payload)
            val localBytes = local.toByteArray()

            central.u32(CENTRAL_SIGNATURE); central.u16(item.entry.versionMadeBy); central.u16(20)
            central.u16(flags); central.u16(method)
            central.u16(item.entry.modTime); central.u16(item.entry.modDate)
            central.u32(0); central.u32(item.payload.size.toLong())
            central.u32(item.plaintextSize.toLong()); central.u16(name.size); central.u16(extra.size)
            central.u16(0); central.u16(0)
            central.u16(item.entry.internalAttributes); central.u32(item.entry.externalAttributes)
            central.u32(offset.toLong())
            central.write(name); central.write(extra)

            output.write(localBytes)
            offset += localBytes.size
        }

        val centralBytes = central.toByteArray()
        output.write(centralBytes)
        output.u32(EOCD_SIGNATURE); output.u16(0); output.u16(0)
        output.u16(entries.size); output.u16(entries.size)
        output.u32(centralBytes.size.toLong()); output.u32(offset.toLong()); output.u16(0)
        return output.toByteArray()
    }

    private fun aesExtraField(actualMethod: Int): ByteArray {
        val field = ByteArrayOutputStream()
        field.u16(0x9901)
        field.u16(7)
        field.u16(2)                      // AE-2
        field.write("AE".toByteArray(Charsets.US_ASCII))
        field.write(3)                    // 3 = AES-256
        field.u16(actualMethod)
        return field.toByteArray()
    }

    fun crc32(data: ByteArray): Long = CRC32().apply { update(data) }.value
}

private fun ByteArrayOutputStream.u16(value: Int) {
    write(value and 0xFF); write((value shr 8) and 0xFF)
}

private fun ByteArrayOutputStream.u32(value: Long) {
    write((value and 0xFF).toInt()); write(((value shr 8) and 0xFF).toInt())
    write(((value shr 16) and 0xFF).toInt()); write(((value shr 24) and 0xFF).toInt())
}
