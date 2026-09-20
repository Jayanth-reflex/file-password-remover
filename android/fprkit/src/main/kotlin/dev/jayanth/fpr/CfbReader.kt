package dev.jayanth.fpr

import java.io.ByteArrayOutputStream

/**
 * Reader for the Compound File Binary format ([MS-CFB]).
 *
 * Encrypted OOXML documents and Word/Excel 97-2003 files are both CFB
 * containers: a small FAT filesystem inside one file. Only reading is
 * implemented, because that is all decryption needs.
 */
class CfbReader(private val data: ByteArray) {

    data class DirectoryEntry(
        val name: String,
        val type: Int,          // 0 empty, 1 storage, 2 stream, 5 root
        val startSector: Long,
        val size: Long,
    )

    private val sectorSize: Int
    private val miniSectorSize: Int
    private val miniStreamCutoff: Long
    private val fat: LongArray
    private val miniFat: LongArray
    private val directory: List<DirectoryEntry>
    private val miniStream: ByteArray

    init {
        require(isCfb(data)) { "not a compound file" }
        val header = ByteReader(data, 30)
        sectorSize = 1 shl header.u16()
        miniSectorSize = 1 shl header.u16()
        if (sectorSize < 128 || sectorSize > (1 shl 20)) {
            throw FprException.CorruptFile("implausible sector size $sectorSize")
        }

        header.seek(44)
        val fatSectorCount = header.u32().toInt()
        val firstDirectorySector = header.u32()
        header.seek(56)
        miniStreamCutoff = header.u32()
        val firstMiniFatSector = header.u32()
        val miniFatSectorCount = header.u32().toInt()
        val firstDifatSector = header.u32()
        val difatSectorCount = header.u32().toInt()

        val difat = ArrayList<Long>()
        val entry = ByteReader(data, 76)
        repeat(109) {
            val sector = entry.u32()
            if (sector != FREE_SECTOR) difat.add(sector)
        }
        var nextDifat = firstDifatSector
        var guard = 0
        while (nextDifat != END_OF_CHAIN && nextDifat != FREE_SECTOR && guard <= difatSectorCount) {
            val reader = ByteReader(data, sectorOffset(nextDifat))
            repeat(sectorSize / 4 - 1) {
                val sector = reader.u32()
                if (sector != FREE_SECTOR) difat.add(sector)
            }
            nextDifat = reader.u32()
            guard += 1
        }

        val fatValues = ArrayList<Long>(fatSectorCount * sectorSize / 4)
        for (sector in difat) {
            val reader = ByteReader(data, sectorOffset(sector))
            repeat(sectorSize / 4) {
                fatValues.add(runCatching { reader.u32() }.getOrDefault(FREE_SECTOR))
            }
        }
        fat = fatValues.toLongArray()

        miniFat = readChain(firstMiniFatSector).let { bytes ->
            val reader = ByteReader(bytes)
            val values = ArrayList<Long>()
            while (reader.remaining >= 4) values.add(reader.u32())
            values.toLongArray()
        }

        val directoryBytes = readChain(firstDirectorySector)
        val entries = ArrayList<DirectoryEntry>()
        var cursor = 0
        while (cursor + 128 <= directoryBytes.size) {
            val block = directoryBytes.copyOfRange(cursor, cursor + 128)
            val reader = ByteReader(block, 64)
            val nameLength = reader.u16()
            val type = reader.u8()
            reader.seek(116)
            val startSector = reader.u32()
            val size = reader.u64()
            val nameBytes = block.copyOfRange(0, maxOf(0, minOf(64, nameLength - 2)))
            entries.add(
                DirectoryEntry(String(nameBytes, Charsets.UTF_16LE), type, startSector, size)
            )
            cursor += 128
        }
        directory = entries

        val root = entries.firstOrNull { it.type == 5 }
        miniStream = if (root != null && root.size > 0) {
            readChain(root.startSector).copyOf(minOf(root.size.toInt(), Int.MAX_VALUE))
        } else {
            ByteArray(0)
        }
    }

    fun hasStream(name: String): Boolean = directory.any { it.type == 2 && it.name == name }

    fun stream(name: String): ByteArray {
        val entry = directory.firstOrNull { it.type == 2 && it.name == name }
            ?: throw FprException.CorruptFile("stream '$name' not found in compound file")
        if (entry.size < miniStreamCutoff) {
            val output = ByteArrayOutputStream()
            var sector = entry.startSector
            var guard = 0
            while (sector != END_OF_CHAIN && sector != FREE_SECTOR && guard <= miniFat.size) {
                val start = sector.toInt() * miniSectorSize
                if (start + miniSectorSize > miniStream.size) break
                output.write(miniStream, start, miniSectorSize)
                sector = if (sector < miniFat.size) miniFat[sector.toInt()] else END_OF_CHAIN
                guard += 1
            }
            return output.toByteArray().copyOf(entry.size.toInt())
        }
        return readChain(entry.startSector).copyOf(entry.size.toInt())
    }

    private fun sectorOffset(sector: Long): Int = ((sector + 1) * sectorSize).toInt()

    private fun readChain(start: Long): ByteArray {
        val output = ByteArrayOutputStream()
        var sector = start
        var visited = 0
        while (sector != END_OF_CHAIN && sector != FREE_SECTOR && visited <= fat.size) {
            val begin = sectorOffset(sector)
            if (begin + sectorSize > data.size) break
            output.write(data, begin, sectorSize)
            if (sector >= fat.size) break
            sector = fat[sector.toInt()]
            visited += 1
        }
        return output.toByteArray()
    }

    companion object {
        private const val END_OF_CHAIN = 0xFFFFFFFEL
        private const val FREE_SECTOR = 0xFFFFFFFFL
        private val SIGNATURE = byteArrayOf(
            0xD0.toByte(), 0xCF.toByte(), 0x11, 0xE0.toByte(),
            0xA1.toByte(), 0xB1.toByte(), 0x1A, 0xE1.toByte(),
        )

        fun isCfb(data: ByteArray): Boolean =
            data.size >= 8 && SIGNATURE.indices.all { data[it] == SIGNATURE[it] }
    }
}
