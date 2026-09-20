import CommonCrypto
import CryptoKit
import Foundation

enum Crypto {
    /// PBKDF2-HMAC-SHA1. WinZip AES fixes the iteration count at 1000.
    ///
    /// Written out rather than called through CommonCrypto so the derivation is
    /// readable next to the spec it implements (RFC 2898, section 5.2).
    static func pbkdf2SHA1(password: Data, salt: Data, iterations: Int, length: Int) -> Data {
        let key = SymmetricKey(data: password)
        var output = Data()
        var block: UInt32 = 1
        while output.count < length {
            var salted = salt
            salted.append(contentsOf: [
                UInt8((block >> 24) & 0xFF), UInt8((block >> 16) & 0xFF),
                UInt8((block >> 8) & 0xFF), UInt8(block & 0xFF),
            ])
            var current = Data(HMAC<Insecure.SHA1>.authenticationCode(for: salted, using: key))
            var accumulator = [UInt8](current)
            for _ in 1..<iterations {
                current = Data(HMAC<Insecure.SHA1>.authenticationCode(for: current, using: key))
                for (index, byte) in current.enumerated() { accumulator[index] ^= byte }
            }
            output.append(contentsOf: accumulator)
            block += 1
        }
        return output.prefix(length)
    }

    /// Raw AES-ECB over whole blocks. Only ever used to generate a CTR keystream.
    static func aesECBEncrypt(_ input: Data, key: Data) throws -> Data {
        var output = Data(count: input.count)
        let capacity = output.count
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBuffer in
            input.withUnsafeBytes { inBuffer in
                key.withUnsafeBytes { keyBuffer in
                    CCCrypt(
                        CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBuffer.baseAddress, key.count, nil,
                        inBuffer.baseAddress, input.count,
                        outBuffer.baseAddress, capacity, &moved
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw FprError.internalError("AES-ECB failed with status \(status)")
        }
        return output.prefix(moved)
    }

    /// WinZip AES counter mode.
    ///
    /// The counter is 128-bit **little-endian starting at 1**, which is where
    /// this differs from NIST CTR and from most library CTR implementations --
    /// the reason the keystream is built by hand here.
    static func winZipAESCrypt(_ input: Data, key: Data) throws -> Data {
        let blockCount = (input.count + 15) / 16
        var counters = Data(capacity: blockCount * 16)
        for index in 1...max(blockCount, 1) {
            var counter = UInt64(index)
            var block = [UInt8](repeating: 0, count: 16)
            for position in 0..<8 {
                block[position] = UInt8(counter & 0xFF)
                counter >>= 8
            }
            counters.append(contentsOf: block)
        }
        let keystream = try aesECBEncrypt(counters, key: key)
        var output = [UInt8](input)
        let stream = [UInt8](keystream)
        for index in 0..<output.count { output[index] ^= stream[index] }
        return Data(output)
    }

    static func hmacSHA1(_ message: Data, key: Data) -> Data {
        Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// Constant-time comparison, so a wrong password cannot be narrowed by timing.
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }
}

/// Legacy PKWARE ZipCrypto. Weak by modern standards, still common in the wild.
///
/// This decrypts with a password the user supplies. It does not attack the
/// cipher: the known-plaintext weakness of ZipCrypto is deliberately not used.
struct ZipCryptoStream {
    private var key0: UInt32 = 0x1234_5678
    private var key1: UInt32 = 0x2345_6789
    private var key2: UInt32 = 0x3456_7890

    init(password: Data) {
        for byte in password { updateKeys(byte) }
    }

    private mutating func updateKeys(_ byte: UInt8) {
        key0 = Self.crc32(key0, byte)
        key1 = key1 &+ (key0 & 0xFF)
        key1 = key1 &* 134_775_813 &+ 1
        key2 = Self.crc32(key2, UInt8((key1 >> 24) & 0xFF))
    }

    private var decryptByte: UInt8 {
        // temp is 16-bit, but the product is taken at full width before the
        // shift -- truncating to 16 bits first silently drops the bits that
        // actually end up in the output byte.
        let temp = UInt32((key2 | 2) & 0xFFFF)
        return UInt8(((temp &* (temp ^ 1)) >> 8) & 0xFF)
    }

    mutating func decrypt(_ input: Data) -> Data {
        var output = [UInt8](repeating: 0, count: input.count)
        for (index, byte) in input.enumerated() {
            let plain = byte ^ decryptByte
            updateKeys(plain)
            output[index] = plain
        }
        return Data(output)
    }

    private static func crc32(_ crc: UInt32, _ byte: UInt8) -> UInt32 {
        (crc >> 8) ^ CRC32.table[Int((crc ^ UInt32(byte)) & 0xFF)]
    }
}

enum CRC32 {
    static let table: [UInt32] = {
        (0..<256).map { index -> UInt32 in
            var value = UInt32(index)
            for _ in 0..<8 {
                value = (value & 1) == 1 ? (value >> 1) ^ 0xEDB8_8320 : value >> 1
            }
            return value
        }
    }()

    static func checksum(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc = (crc >> 8) ^ table[Int((crc ^ UInt32(byte)) & 0xFF)]
        }
        return crc ^ 0xFFFF_FFFF
    }
}

extension Crypto {
    /// AES-CBC with **no padding**. [MS-OFFCRYPTO] zero-pads to the block size
    /// rather than using PKCS#7, so padding is handled by the caller.
    static func aesCBCDecrypt(_ input: Data, key: Data, iv: Data) throws -> Data {
        guard input.count % 16 == 0 else {
            throw FprError.corruptFile("AES-CBC input is not a whole number of blocks")
        }
        var output = Data(count: input.count)
        let capacity = output.count
        var moved = 0
        let status = output.withUnsafeMutableBytes { outBuffer in
            input.withUnsafeBytes { inBuffer in
                key.withUnsafeBytes { keyBuffer in
                    iv.withUnsafeBytes { ivBuffer in
                        CCCrypt(
                            CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                            keyBuffer.baseAddress, key.count, ivBuffer.baseAddress,
                            inBuffer.baseAddress, input.count,
                            outBuffer.baseAddress, capacity, &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw FprError.internalError("AES-CBC failed with status \(status)")
        }
        return output.prefix(moved)
    }

    static func sha512(_ data: Data) -> Data { Data(SHA512.hash(data: data)) }
}
