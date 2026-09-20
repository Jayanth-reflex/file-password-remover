import Compression
import Foundation

enum Deflate {
    /// Raw DEFLATE (no zlib wrapper), which is what a ZIP entry stores.
    static func inflate(_ input: Data, expectedSize: Int) throws -> Data {
        guard !input.isEmpty else { return Data() }
        // A corrupt stream must not be able to make us allocate without bound.
        let capacity = max(expectedSize, input.count * 4) + 64
        var output = Data(count: capacity)
        let written = output.withUnsafeMutableBytes { outBuffer -> Int in
            input.withUnsafeBytes { inBuffer -> Int in
                compression_decode_buffer(
                    outBuffer.bindMemory(to: UInt8.self).baseAddress!, capacity,
                    inBuffer.bindMemory(to: UInt8.self).baseAddress!, input.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0 || expectedSize == 0 else {
            throw FprError.corruptFile("DEFLATE stream did not decompress")
        }
        return output.prefix(written)
    }

    static func deflate(_ input: Data) throws -> Data {
        guard !input.isEmpty else { return Data() }
        let capacity = input.count + input.count / 2 + 64
        var output = Data(count: capacity)
        let written = output.withUnsafeMutableBytes { outBuffer -> Int in
            input.withUnsafeBytes { inBuffer -> Int in
                compression_encode_buffer(
                    outBuffer.bindMemory(to: UInt8.self).baseAddress!, capacity,
                    inBuffer.bindMemory(to: UInt8.self).baseAddress!, input.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0 else { throw FprError.internalError("DEFLATE compression failed") }
        return output.prefix(written)
    }
}
