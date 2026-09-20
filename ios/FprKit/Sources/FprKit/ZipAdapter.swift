import Foundation
import Security

/// ZIP archives: WinZip AES (AE-1/AE-2) and legacy PKWARE ZipCrypto.
public struct ZipAdapter: Sendable {
    public init() {}

    /// Decrypt every encrypted entry and return a new archive with no encryption.
    ///
    /// The password is required and is never guessed. A wrong password fails
    /// here and produces nothing -- there is no retry loop to build around.
    public func remove(_ data: Data, password: String) throws -> Data {
        let entries = try ZipStructure.readCentralDirectory(data)
        guard entries.contains(where: \.isEncrypted) else {
            throw FprError.policyRefused("This ZIP is not encrypted; there is nothing to remove.")
        }
        let passwordData = Data(password.utf8)

        var decrypted: [DecryptedEntry] = []
        for entry in entries {
            let start = try ZipStructure.payloadOffset(data, entry: entry)
            let end = start + Int(entry.compressedSize)
            guard end <= data.count else {
                throw FprError.corruptFile("payload of \(entry.name) runs past end of file")
            }
            let payload = data.subdata(in: (data.startIndex + start)..<(data.startIndex + end))

            let compressed: Data
            if entry.isEncrypted {
                if let aes = entry.aes {
                    compressed = try decryptAES(payload, aes: aes, password: passwordData, name: entry.name)
                } else {
                    compressed = try decryptZipCrypto(payload, password: passwordData, entry: entry)
                }
            } else {
                compressed = payload
            }

            let method = entry.effectiveMethod
            let plaintext = try ZipArchiveReader.decompress(
                compressed, method: method, expectedSize: Int(entry.uncompressedSize)
            )
            decrypted.append(
                DecryptedEntry(
                    entry: entry, compressed: compressed, plaintextSize: plaintext.count,
                    // AE-2 zeroes the stored CRC, so it is recomputed from the
                    // recovered plaintext rather than trusted.
                    crc: CRC32.checksum(plaintext), method: method
                )
            )
        }
        return try ZipArchiveWriter.write(decrypted)
    }

    private func decryptAES(
        _ payload: Data, aes: AESExtraField, password: Data, name: String
    ) throws -> Data {
        let keyLength = aes.keyBits / 8
        guard payload.count >= aes.saltLength + 2 + 10 else {
            throw FprError.corruptFile("AES payload of \(name) is too short")
        }
        var reader = ByteReader(payload)
        let salt = try reader.bytes(aes.saltLength)
        let verifier = try reader.bytes(2)
        let ciphertext = try reader.bytes(payload.count - aes.saltLength - 2 - 10)
        let authCode = try reader.bytes(10)

        let derived = Crypto.pbkdf2SHA1(
            password: password, salt: salt, iterations: 1000, length: keyLength * 2 + 2
        )
        let encryptionKey = derived.prefix(keyLength)
        let authenticationKey = derived.dropFirst(keyLength).prefix(keyLength)
        let expectedVerifier = derived.suffix(2)

        guard Crypto.constantTimeEquals(Data(expectedVerifier), verifier) else {
            throw FprError.wrongPassword
        }
        // The 2-byte verifier accepts 1 wrong password in 65536; the MAC is what
        // actually decides, so it is always checked.
        let mac = Crypto.hmacSHA1(ciphertext, key: Data(authenticationKey)).prefix(10)
        guard Crypto.constantTimeEquals(Data(mac), authCode) else {
            throw FprError.wrongPassword
        }
        return try Crypto.winZipAESCrypt(ciphertext, key: Data(encryptionKey))
    }

    private func decryptZipCrypto(
        _ payload: Data, password: Data, entry: ZipEntry
    ) throws -> Data {
        guard payload.count >= 12 else {
            throw FprError.corruptFile("ZipCrypto payload of \(entry.name) is too short")
        }
        var stream = ZipCryptoStream(password: password)
        let header = stream.decrypt(payload.prefix(12))
        // Bit 3 means the CRC was not known when writing, so the check byte is
        // the high byte of the DOS time instead. ([APPNOTE] 6.1.6.)
        let expected: UInt8 =
            entry.flags & 0x8 != 0
            ? UInt8((entry.modTime >> 8) & 0xFF)
            : UInt8((entry.crc >> 24) & 0xFF)
        guard header[header.startIndex + 11] == expected else {
            throw FprError.wrongPassword
        }
        return stream.decrypt(payload.dropFirst(12))
    }

    /// Rewrite the archive with every entry under WinZip AES-256.
    ///
    /// Entries are re-deflated rather than copied, because the stored stream
    /// has to change: AE-2 encrypts the *compressed* bytes and zeroes the CRC
    /// in the header, so nothing from the original entry can be reused as-is.
    public func protect(_ data: Data, password: String) throws -> Data {
        let entries = try ZipStructure.readCentralDirectory(data)
        guard !entries.contains(where: \.isEncrypted) else {
            throw FprError.policyRefused(
                "This ZIP is already encrypted. Remove the existing protection first."
            )
        }
        let passwordData = Data(password.utf8)

        var output = Data()
        var central = Data()
        var count = 0

        for entry in entries {
            let payload = try ZipStructure.payloadOffset(data, entry: entry)
            let end = payload + Int(entry.compressedSize)
            guard end <= data.count else {
                throw FprError.corruptFile("payload of \(entry.name) runs past end of file")
            }
            let stored = data.subdata(in: (data.startIndex + payload)..<(data.startIndex + end))
            let plaintext = try ZipArchiveReader.decompress(
                stored, method: entry.method, expectedSize: Int(entry.uncompressedSize)
            )

            let nameData = Data(entry.name.utf8)
            let isDirectory = entry.name.hasSuffix("/")
            let method: UInt16 = isDirectory ? 0 : 8
            let compressed = isDirectory ? Data() : try Deflate.deflate(plaintext)
            let encrypted = isDirectory
                ? Data()
                : try Self.encryptAES(compressed, password: passwordData)

            // Method 99 marks "see the AES extra field"; the real method moves
            // into that field.
            let extra = Self.aesExtraField(actualMethod: method)
            let flags: UInt16 = isDirectory ? 0 : 0x1
            let localOffset = UInt32(output.count)
            let storedMethod: UInt16 = isDirectory ? 0 : 99
            // AE-2 zeroes the CRC in the headers: the authentication code is
            // what proves integrity, and a CRC would leak a check on the
            // plaintext to anyone without the password.
            let crc: UInt32 = 0

            func header(_ signature: UInt32, central isCentral: Bool) -> Data {
                var block = Data()
                block.append(u32: signature)
                if isCentral { block.append(u16: 20) }
                block.append(u16: 20)
                block.append(u16: flags)
                block.append(u16: storedMethod)
                block.append(u16: entry.modTime)
                block.append(u16: entry.modDate)
                block.append(u32: crc)
                block.append(u32: UInt32(encrypted.count))
                block.append(u32: UInt32(plaintext.count))
                block.append(u16: UInt16(nameData.count))
                block.append(u16: UInt16(isDirectory ? 0 : extra.count))
                return block
            }

            output.append(header(ZipStructure.localSignature, central: false))
            output.append(nameData)
            if !isDirectory { output.append(extra) }
            output.append(encrypted)

            central.append(header(ZipStructure.centralSignature, central: true))
            central.append(u16: 0)                       // comment length
            central.append(u16: 0)                       // disk number start
            central.append(u16: entry.internalAttributes)
            central.append(u32: entry.externalAttributes)
            central.append(u32: localOffset)
            central.append(nameData)
            if !isDirectory { central.append(extra) }
            count += 1
        }

        let centralOffset = UInt32(output.count)
        output.append(central)
        output.append(u32: ZipStructure.eocdSignature)
        output.append(u16: 0)
        output.append(u16: 0)
        output.append(u16: UInt16(count))
        output.append(u16: UInt16(count))
        output.append(u32: UInt32(central.count))
        output.append(u32: centralOffset)
        output.append(u16: 0)
        return output
    }

    /// salt | password verifier | ciphertext | truncated HMAC, per the AE spec.
    private static func encryptAES(_ plaintext: Data, password: Data) throws -> Data {
        let keyLength = 32  // AES-256
        var salt = Data(count: 16)
        let status = salt.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 16, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw FprError.internalError("the system random number generator failed")
        }

        let derived = Crypto.pbkdf2SHA1(
            password: password, salt: salt, iterations: 1000, length: keyLength * 2 + 2
        )
        let encryptionKey = Data(derived.prefix(keyLength))
        let authenticationKey = Data(derived.dropFirst(keyLength).prefix(keyLength))
        let verifier = Data(derived.suffix(2))

        let ciphertext = try Crypto.winZipAESEncrypt(plaintext, key: encryptionKey)
        let mac = Crypto.hmacSHA1(ciphertext, key: authenticationKey).prefix(10)

        var payload = salt
        payload.append(verifier)
        payload.append(ciphertext)
        payload.append(mac)
        return payload
    }

    private static func aesExtraField(actualMethod: UInt16) -> Data {
        var field = Data()
        field.append(u16: 0x9901)
        field.append(u16: 7)
        field.append(u16: 2)                       // AE-2
        field.append(Data("AE".utf8))
        field.append(3)                            // 3 = AES-256
        field.append(u16: actualMethod)
        return field
    }

    public func detect(_ data: Data) throws -> Detection {
        let entries = try ZipStructure.readCentralDirectory(data)
        let encrypted = entries.filter(\.isEncrypted)

        guard !encrypted.isEmpty else {
            return Detection(
                format: .zip, protection: .none, removability: .notProtected,
                detail: "Not encrypted. \(entries.count) entr\(entries.count == 1 ? "y" : "ies")."
            )
        }

        if let strong = encrypted.first(where: { $0.usesStrongEncryption && $0.aes == nil }) {
            return Detection(
                format: .zip, protection: .unknown, removability: .unsupported,
                detail: """
                    '\(strong.name)' uses PKWare Strong Encryption (SES), which is \
                    certificate-based and not supported.
                    """
            )
        }

        let aesFields = encrypted.compactMap(\.aes)
        let algorithm: String
        if let aes = aesFields.first, aesFields.count == encrypted.count {
            algorithm = "AES-\(aes.keyBits) (WinZip AE-\(aes.vendorVersion))"
        } else if aesFields.isEmpty {
            algorithm = "ZipCrypto (legacy PKWARE)"
        } else {
            algorithm = "mixed: AES and ZipCrypto"
        }

        let plural = encrypted.count == 1 ? "entry is" : "entries are"
        return Detection(
            format: .zip, protection: .userPassword, removability: .removable,
            algorithm: algorithm,
            detail: "\(encrypted.count) of \(entries.count) \(plural) encrypted. Supply the password."
        )
    }
}
