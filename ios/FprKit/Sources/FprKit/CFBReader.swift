import Foundation

/// Reader for the Compound File Binary format ([MS-CFB]).
///
/// Both encrypted OOXML documents and Word/Excel 97-2003 files are CFB
/// containers: a little FAT filesystem inside a single file. Only the reading
/// half is implemented, because that is all decryption needs.
struct CFBReader {
    private static let signature: [UInt8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
    private static let endOfChain: UInt32 = 0xFFFF_FFFE
    private static let freeSector: UInt32 = 0xFFFF_FFFF

    struct DirectoryEntry {
        let name: String
        let type: UInt8       // 0 empty, 1 storage, 2 stream, 5 root
        let startSector: UInt32
        let size: UInt64
    }

    private let data: Data
    private let sectorSize: Int
    private let miniSectorSize: Int
    private let miniStreamCutoff: UInt32
    private let fat: [UInt32]
    private let miniFAT: [UInt32]
    private let directory: [DirectoryEntry]
    private let miniStream: Data

    static func isCFB(_ data: Data) -> Bool {
        data.count >= 8 && [UInt8](data.prefix(8)) == signature
    }

    init(_ data: Data) throws {
        guard Self.isCFB(data) else {
            throw FprError.corruptFile("not a compound file (bad signature)")
        }
        self.data = data

        var header = ByteReader(data, offset: 30)
        sectorSize = 1 << Int(try header.u16())
        miniSectorSize = 1 << Int(try header.u16())
        guard sectorSize >= 128, sectorSize <= 1 << 20 else {
            throw FprError.corruptFile("implausible sector size \(sectorSize)")
        }

        try header.seek(44)
        let fatSectorCount = Int(try header.u32())
        let firstDirectorySector = try header.u32()
        try header.seek(56)
        miniStreamCutoff = try header.u32()
        let firstMiniFATSector = try header.u32()
        let miniFATSectorCount = Int(try header.u32())
        let firstDIFATSector = try header.u32()
        let difatSectorCount = Int(try header.u32())

        // --- DIFAT: the list of sectors that hold the FAT.
        var difat: [UInt32] = []
        var entry = ByteReader(data, offset: 76)
        for _ in 0..<109 {
            let sector = try entry.u32()
            if sector == Self.freeSector { break }
            difat.append(sector)
        }
        var nextDIFAT = firstDIFATSector
        var difatGuard = 0
        while nextDIFAT != Self.endOfChain, nextDIFAT != Self.freeSector,
              difatGuard < difatSectorCount + 1 {
            var reader = ByteReader(data, offset: Self.offset(of: nextDIFAT, sectorSize))
            for _ in 0..<((sectorSize / 4) - 1) {
                let sector = try reader.u32()
                if sector != Self.freeSector { difat.append(sector) }
            }
            nextDIFAT = try reader.u32()
            difatGuard += 1
        }

        // --- FAT: the sector chains.
        var fatEntries: [UInt32] = []
        fatEntries.reserveCapacity(fatSectorCount * sectorSize / 4)
        for sector in difat.prefix(max(fatSectorCount, difat.count)) {
            var reader = ByteReader(data, offset: Self.offset(of: sector, sectorSize))
            for _ in 0..<(sectorSize / 4) {
                fatEntries.append((try? reader.u32()) ?? Self.freeSector)
            }
        }
        fat = fatEntries

        // --- MiniFAT, for streams below the cutoff.
        miniFAT = try Self.readChainValues(
            data: data, fat: fat, start: firstMiniFATSector,
            sectorSize: sectorSize, limit: miniFATSectorCount
        )

        // --- Directory.
        let directoryBytes = try Self.readChain(
            data: data, fat: fat, start: firstDirectorySector, sectorSize: sectorSize
        )
        var entries: [DirectoryEntry] = []
        var cursor = 0
        while cursor + 128 <= directoryBytes.count {
            let block = directoryBytes.subdata(
                in: (directoryBytes.startIndex + cursor)..<(directoryBytes.startIndex + cursor + 128)
            )
            var reader = ByteReader(block, offset: 64)
            let nameLength = Int(try reader.u16())
            let type = try reader.u8()
            try reader.seek(116)
            let startSector = try reader.u32()
            let size = try reader.u64()
            let rawName = block.prefix(max(0, min(64, nameLength - 2)))
            let name = String(data: Data(rawName), encoding: .utf16LittleEndian) ?? ""
            entries.append(
                DirectoryEntry(name: name, type: type, startSector: startSector, size: size)
            )
            cursor += 128
        }
        directory = entries

        // --- The mini stream itself lives in the root entry.
        if let root = entries.first(where: { $0.type == 5 }), root.size > 0 {
            miniStream = try Self.readChain(
                data: data, fat: fat, start: root.startSector, sectorSize: sectorSize
            ).prefix(Int(root.size))
        } else {
            miniStream = Data()
        }
    }

    /// Stream contents by name. Names are unique enough in the containers we
    /// care about that a flat search beats walking the red-black tree.
    func stream(named name: String) throws -> Data {
        guard let entry = directory.first(where: { $0.type == 2 && $0.name == name }) else {
            throw FprError.corruptFile("stream '\(name)' not found in compound file")
        }
        if entry.size < UInt64(miniStreamCutoff) {
            var output = Data()
            var sector = entry.startSector
            var guardCount = 0
            while sector != Self.endOfChain, sector != Self.freeSector,
                  guardCount < miniFAT.count + 1 {
                let start = Int(sector) * miniSectorSize
                guard start + miniSectorSize <= miniStream.count else { break }
                output.append(
                    miniStream.subdata(
                        in: (miniStream.startIndex + start)..<(miniStream.startIndex + start + miniSectorSize)
                    )
                )
                sector = Int(sector) < miniFAT.count ? miniFAT[Int(sector)] : Self.endOfChain
                guardCount += 1
            }
            return output.prefix(Int(entry.size))
        }
        return try Self.readChain(
            data: data, fat: fat, start: entry.startSector, sectorSize: sectorSize
        ).prefix(Int(entry.size))
    }

    func hasStream(named name: String) -> Bool {
        directory.contains { $0.type == 2 && $0.name == name }
    }

    private static func offset(of sector: UInt32, _ sectorSize: Int) -> Int {
        (Int(sector) + 1) * sectorSize
    }

    private static func readChain(
        data: Data, fat: [UInt32], start: UInt32, sectorSize: Int
    ) throws -> Data {
        var output = Data()
        var sector = start
        var visited = 0
        while sector != endOfChain, sector != freeSector, visited <= fat.count {
            let begin = offset(of: sector, sectorSize)
            guard begin + sectorSize <= data.count else { break }
            output.append(
                data.subdata(in: (data.startIndex + begin)..<(data.startIndex + begin + sectorSize))
            )
            guard Int(sector) < fat.count else { break }
            sector = fat[Int(sector)]
            visited += 1
        }
        return output
    }

    private static func readChainValues(
        data: Data, fat: [UInt32], start: UInt32, sectorSize: Int, limit: Int
    ) throws -> [UInt32] {
        let bytes = try readChain(data: data, fat: fat, start: start, sectorSize: sectorSize)
        var reader = ByteReader(bytes)
        var values: [UInt32] = []
        while reader.remaining >= 4, let value = try? reader.u32() { values.append(value) }
        return values
    }
}
