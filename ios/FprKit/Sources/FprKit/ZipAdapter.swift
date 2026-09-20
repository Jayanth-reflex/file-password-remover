import Foundation

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
