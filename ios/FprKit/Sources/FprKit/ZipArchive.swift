import Foundation

/// A decrypted entry, ready to be written back out.
struct DecryptedEntry {
    var entry: ZipEntry
    /// The compressed stream, decrypted but *not* recompressed.
    var compressed: Data
    var plaintextSize: Int
    var crc: UInt32
    var method: UInt16
}

enum ZipArchiveReader {
    /// Read every member's plaintext. Used by tests and, more importantly, by
    /// verification: the output file is re-opened from disk and read back
    /// before success is reported.
    static func readMembers(_ data: Data) throws -> [String: Data] {
        let entries = try ZipStructure.readCentralDirectory(data)
        var members: [String: Data] = [:]
        for entry in entries where !entry.name.hasSuffix("/") {
            guard !entry.isEncrypted else {
                throw FprError.internalError("entry \(entry.name) is still encrypted")
            }
            let start = try ZipStructure.payloadOffset(data, entry: entry)
            let end = start + Int(entry.compressedSize)
            guard end <= data.count else {
                throw FprError.corruptFile("payload of \(entry.name) runs past end of file")
            }
            let payload = data.subdata(in: (data.startIndex + start)..<(data.startIndex + end))
            members[entry.name] = try decompress(
                payload, method: entry.method, expectedSize: Int(entry.uncompressedSize)
            )
        }
        return members
    }

    static func decompress(_ payload: Data, method: UInt16, expectedSize: Int) throws -> Data {
        switch method {
        case 0: return payload
        case 8: return try Deflate.inflate(payload, expectedSize: expectedSize)
        default:
            throw FprError.unsupportedFormat("compression method \(method) is not supported")
        }
    }
}

enum ZipArchiveWriter {
    /// Rebuild an archive from already-decrypted entries.
    ///
    /// The compressed streams are written through untouched, so the output is
    /// byte-identical in content to the input once decrypted -- nothing is
    /// recompressed and no fidelity is lost.
    static func write(_ decrypted: [DecryptedEntry]) throws -> Data {
        var output = Data()
        var central = Data()

        for item in decrypted {
            let nameData = Data(item.entry.name.utf8)
            let localOffset = UInt32(output.count)
            // Strip encryption bit 0 and the "data descriptor" bit 3: sizes are
            // known here, so a descriptor would be a lie.
            let flags = item.entry.flags & ~UInt16(0x1) & ~UInt16(0x8) & ~UInt16(0x40)
            let extra = strippedExtra(item.entry.extra)

            output.append(u32: ZipStructure.localSignature)
            output.append(u16: 20)
            output.append(u16: flags)
            output.append(u16: item.method)
            output.append(u16: item.entry.modTime)
            output.append(u16: item.entry.modDate)
            output.append(u32: item.crc)
            output.append(u32: UInt32(item.compressed.count))
            output.append(u32: UInt32(item.plaintextSize))
            output.append(u16: UInt16(nameData.count))
            output.append(u16: UInt16(extra.count))
            output.append(nameData)
            output.append(extra)
            output.append(item.compressed)

            central.append(u32: ZipStructure.centralSignature)
            central.append(u16: item.entry.versionMadeBy)
            central.append(u16: 20)
            central.append(u16: flags)
            central.append(u16: item.method)
            central.append(u16: item.entry.modTime)
            central.append(u16: item.entry.modDate)
            central.append(u32: item.crc)
            central.append(u32: UInt32(item.compressed.count))
            central.append(u32: UInt32(item.plaintextSize))
            central.append(u16: UInt16(nameData.count))
            central.append(u16: UInt16(extra.count))
            central.append(u16: UInt16(item.entry.comment.count))
            central.append(u16: 0)
            central.append(u16: item.entry.internalAttributes)
            central.append(u32: item.entry.externalAttributes)
            central.append(u32: localOffset)
            central.append(nameData)
            central.append(extra)
            central.append(item.entry.comment)
        }

        let centralOffset = UInt32(output.count)
        output.append(central)
        output.append(u32: ZipStructure.eocdSignature)
        output.append(u16: 0)
        output.append(u16: 0)
        output.append(u16: UInt16(decrypted.count))
        output.append(u16: UInt16(decrypted.count))
        output.append(u32: UInt32(central.count))
        output.append(u32: centralOffset)
        output.append(u16: 0)
        return output
    }

    /// Drop the WinZip AES extra field: keeping it would describe encryption
    /// that is no longer there.
    private static func strippedExtra(_ extra: Data) -> Data {
        var reader = ByteReader(extra)
        var kept = Data()
        while reader.remaining >= 4 {
            guard let headerID = try? reader.u16(), let size = try? reader.u16(),
                  let payload = try? reader.bytes(Int(size)) else { break }
            guard headerID != 0x9901 else { continue }
            kept.append(u16: headerID)
            kept.append(u16: UInt16(payload.count))
            kept.append(payload)
        }
        return kept
    }
}

extension Data {
    mutating func append(u16 value: UInt16) {
        append(contentsOf: [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)])
    }

    mutating func append(u32 value: UInt32) {
        append(contentsOf: [
            UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF),
        ])
    }
}
