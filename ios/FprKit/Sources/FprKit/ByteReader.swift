import Foundation

/// Bounds-checked little-endian reader.
///
/// Every archive format here is parsed from attacker-supplied bytes, so every
/// read is checked and a short buffer becomes `corruptFile` rather than a
/// crash.
struct ByteReader {
    let data: Data
    private(set) var offset: Int

    init(_ data: Data, offset: Int = 0) {
        self.data = data
        self.offset = offset
    }

    var remaining: Int { data.count - offset }

    mutating func seek(_ to: Int) throws {
        guard to >= 0, to <= data.count else {
            throw FprError.corruptFile("offset \(to) outside file of \(data.count) bytes")
        }
        offset = to
    }

    mutating func bytes(_ count: Int) throws -> Data {
        guard count >= 0, remaining >= count else {
            throw FprError.corruptFile("wanted \(count) bytes, \(remaining) left")
        }
        let start = data.startIndex + offset
        offset += count
        return data.subdata(in: start..<(start + count))
    }

    mutating func u8() throws -> UInt8 { try bytes(1)[0] }

    mutating func u16() throws -> UInt16 {
        let b = try bytes(2)
        return UInt16(b[b.startIndex]) | UInt16(b[b.startIndex + 1]) << 8
    }

    mutating func u32() throws -> UInt32 {
        let b = try bytes(4)
        var value: UInt32 = 0
        for index in (0..<4).reversed() {
            value = value << 8 | UInt32(b[b.startIndex + index])
        }
        return value
    }

    mutating func u64() throws -> UInt64 {
        let lo = try u32()
        let hi = try u32()
        return UInt64(hi) << 32 | UInt64(lo)
    }
}

extension Data {
    /// Last index at which `signature` (little-endian u32) occurs, searching back
    /// from the end. Used to find the end-of-central-directory record, which is
    /// variable-length because of its trailing comment.
    func lastIndex(ofSignature signature: UInt32, searchLimit: Int = 66_000) -> Int? {
        let bytes = [
            UInt8(signature & 0xFF),
            UInt8((signature >> 8) & 0xFF),
            UInt8((signature >> 16) & 0xFF),
            UInt8((signature >> 24) & 0xFF),
        ]
        guard count >= 4 else { return nil }
        let lowest = Swift.max(0, count - searchLimit)
        var index = count - 4
        while index >= lowest {
            if self[startIndex + index] == bytes[0],
               self[startIndex + index + 1] == bytes[1],
               self[startIndex + index + 2] == bytes[2],
               self[startIndex + index + 3] == bytes[3] {
                return index
            }
            index -= 1
        }
        return nil
    }
}
