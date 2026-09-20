import Foundation

/// WinZip AE-x parameters, from the 0x9901 extra field.
struct AESExtraField: Equatable {
    let vendorVersion: UInt16   // 1 = AE-1 (CRC kept), 2 = AE-2 (CRC zeroed)
    let strength: UInt8         // 1 = 128, 2 = 192, 3 = 256
    let actualMethod: UInt16    // the compression method hidden behind method 99

    var keyBits: Int {
        switch strength {
        case 1: return 128
        case 2: return 192
        default: return 256
        }
    }

    /// Salt length in bytes: half the key length, per the WinZip AE spec.
    var saltLength: Int { keyBits / 16 }
}

struct ZipEntry {
    var name: String
    var flags: UInt16
    var method: UInt16
    var modTime: UInt16
    var modDate: UInt16
    var crc: UInt32
    var compressedSize: UInt64
    var uncompressedSize: UInt64
    var localHeaderOffset: UInt64
    var extra: Data
    var comment: Data
    var versionMadeBy: UInt16
    var versionNeeded: UInt16
    var internalAttributes: UInt16
    var externalAttributes: UInt32

    var isEncrypted: Bool { flags & 0x1 != 0 }
    var usesStrongEncryption: Bool { flags & 0x40 != 0 }
    var aes: AESExtraField? { Self.parseAES(extra) }

    /// The compression method actually used for the payload: for AES entries the
    /// visible method is 99 and the real one lives in the extra field.
    var effectiveMethod: UInt16 { aes?.actualMethod ?? method }

    static func parseAES(_ extra: Data) -> AESExtraField? {
        var reader = ByteReader(extra)
        while reader.remaining >= 4 {
            guard let headerID = try? reader.u16(), let size = try? reader.u16() else { return nil }
            guard let payload = try? reader.bytes(Int(size)) else { return nil }
            guard headerID == 0x9901, payload.count >= 7 else { continue }
            var field = ByteReader(payload)
            guard let vendorVersion = try? field.u16(),
                  let vendorID = try? field.bytes(2),
                  let strength = try? field.u8(),
                  let actualMethod = try? field.u16(),
                  vendorID == Data("AE".utf8)
            else { continue }
            return AESExtraField(
                vendorVersion: vendorVersion, strength: strength, actualMethod: actualMethod
            )
        }
        return nil
    }

    /// Zip64 sizes/offsets live in the 0x0001 extra field when the 32-bit
    /// fields are saturated to 0xFFFFFFFF.
    mutating func applyZip64(_ extra: Data) {
        var reader = ByteReader(extra)
        while reader.remaining >= 4 {
            guard let headerID = try? reader.u16(), let size = try? reader.u16(),
                  let payload = try? reader.bytes(Int(size)) else { return }
            guard headerID == 0x0001 else { continue }
            var field = ByteReader(payload)
            if uncompressedSize == 0xFFFF_FFFF, let value = try? field.u64() { uncompressedSize = value }
            if compressedSize == 0xFFFF_FFFF, let value = try? field.u64() { compressedSize = value }
            if localHeaderOffset == 0xFFFF_FFFF, let value = try? field.u64() { localHeaderOffset = value }
            return
        }
    }
}

enum ZipStructure {
    static let centralSignature: UInt32 = 0x0201_4B50
    static let eocdSignature: UInt32 = 0x0605_4B50
    static let eocd64LocatorSignature: UInt32 = 0x0706_4B50
    static let eocd64Signature: UInt32 = 0x0606_4B50
    static let localSignature: UInt32 = 0x0403_4B50

    /// Parse the central directory. This is the authoritative entry list: the
    /// local headers can lie, and for streamed archives they often do.
    static func readCentralDirectory(_ data: Data) throws -> [ZipEntry] {
        guard let eocdOffset = data.lastIndex(ofSignature: eocdSignature) else {
            throw FprError.corruptFile("no end-of-central-directory record: not a ZIP file")
        }
        var reader = ByteReader(data, offset: eocdOffset + 4)
        _ = try reader.u16()  // this disk
        _ = try reader.u16()  // disk with central directory
        _ = try reader.u16()  // entries on this disk
        var entryCount = UInt64(try reader.u16())
        _ = try reader.u32()  // central directory size
        var centralOffset = UInt64(try reader.u32())

        if centralOffset == 0xFFFF_FFFF || entryCount == 0xFFFF {
            (entryCount, centralOffset) = try readZip64Locator(data, eocdOffset: eocdOffset)
        }

        var entries: [ZipEntry] = []
        var cursor = ByteReader(data)
        try cursor.seek(Int(centralOffset))
        for _ in 0..<entryCount {
            guard try cursor.u32() == centralSignature else {
                throw FprError.corruptFile("central directory truncated or misaligned")
            }
            let versionMadeBy = try cursor.u16()
            let versionNeeded = try cursor.u16()
            let flags = try cursor.u16()
            let method = try cursor.u16()
            let modTime = try cursor.u16()
            let modDate = try cursor.u16()
            let crc = try cursor.u32()
            let compressedSize = UInt64(try cursor.u32())
            let uncompressedSize = UInt64(try cursor.u32())
            let nameLength = Int(try cursor.u16())
            let extraLength = Int(try cursor.u16())
            let commentLength = Int(try cursor.u16())
            _ = try cursor.u16()  // disk number start
            let internalAttributes = try cursor.u16()
            let externalAttributes = try cursor.u32()
            let localHeaderOffset = UInt64(try cursor.u32())
            let nameData = try cursor.bytes(nameLength)
            let extra = try cursor.bytes(extraLength)
            let comment = try cursor.bytes(commentLength)

            // Bit 11 selects UTF-8; otherwise the spec says CP437. Falling back
            // to UTF-8 is friendlier than refusing the file over a filename.
            let name = String(data: nameData, encoding: .utf8)
                ?? String(decoding: nameData, as: UTF8.self)

            var entry = ZipEntry(
                name: name, flags: flags, method: method, modTime: modTime, modDate: modDate,
                crc: crc, compressedSize: compressedSize, uncompressedSize: uncompressedSize,
                localHeaderOffset: localHeaderOffset, extra: extra, comment: comment,
                versionMadeBy: versionMadeBy, versionNeeded: versionNeeded,
                internalAttributes: internalAttributes, externalAttributes: externalAttributes
            )
            entry.applyZip64(extra)
            entries.append(entry)
        }
        return entries
    }

    private static func readZip64Locator(
        _ data: Data, eocdOffset: Int
    ) throws -> (entryCount: UInt64, centralOffset: UInt64) {
        guard let locator = data.lastIndex(ofSignature: eocd64LocatorSignature) else {
            throw FprError.corruptFile("Zip64 sizes present but no Zip64 locator")
        }
        var reader = ByteReader(data, offset: locator + 4)
        _ = try reader.u32()  // disk with Zip64 EOCD
        let eocd64Offset = try reader.u64()
        var record = ByteReader(data)
        try record.seek(Int(eocd64Offset))
        guard try record.u32() == eocd64Signature else {
            throw FprError.corruptFile("Zip64 end-of-central-directory record missing")
        }
        _ = try record.u64()  // size of record
        _ = try record.u16()  // version made by
        _ = try record.u16()  // version needed
        _ = try record.u32()  // this disk
        _ = try record.u32()  // disk with central directory
        _ = try record.u64()  // entries on this disk
        let entryCount = try record.u64()
        _ = try record.u64()  // central directory size
        let centralOffset = try record.u64()
        return (entryCount, centralOffset)
    }

    /// Where an entry's payload actually starts, read from its local header
    /// (whose name/extra lengths differ from the central copy).
    static func payloadOffset(_ data: Data, entry: ZipEntry) throws -> Int {
        var reader = ByteReader(data)
        try reader.seek(Int(entry.localHeaderOffset))
        guard try reader.u32() == localSignature else {
            throw FprError.corruptFile("bad local header for \(entry.name)")
        }
        try reader.seek(Int(entry.localHeaderOffset) + 26)
        let nameLength = Int(try reader.u16())
        let extraLength = Int(try reader.u16())
        return Int(entry.localHeaderOffset) + 30 + nameLength + extraLength
    }
}
