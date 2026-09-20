import CryptoKit
import Foundation

/// Office Open XML documents encrypted with ECMA-376 *agile* encryption
/// ([MS-OFFCRYPTO] 2.3.4.10): an AES-encrypted package inside a CFB container,
/// with the key derived by an iterated SHA-512 over the password.
public struct OOXMLAdapter: Sendable {
    public init() {}

    // [MS-OFFCRYPTO] 2.3.4.12 -- block keys that diversify the derived key.
    private static let verifierInputBlockKey = Data([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
    private static let verifierValueBlockKey = Data([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])
    private static let keyValueBlockKey = Data([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])
    private static let segmentLength = 4096

    struct AgileDescriptor {
        var keyDataSalt = Data()
        var keyDataBlockSize = 16
        var spinCount = 100_000
        var passwordSalt = Data()
        var keyBits = 256
        var encryptedVerifierHashInput = Data()
        var encryptedVerifierHashValue = Data()
        var encryptedKeyValue = Data()
        var hashAlgorithm = "SHA512"
        var cipherAlgorithm = "AES"
    }

    public func detect(_ data: Data) throws -> Detection {
        if CFBReader.isCFB(data) {
            let container = try CFBReader(data)
            guard container.hasStream(named: "EncryptionInfo") else {
                return Detection(
                    format: .ooxml, protection: .unknown, removability: .unsupported,
                    detail: "Compound file without an EncryptionInfo stream."
                )
            }
            let descriptor = try readDescriptor(container)
            return Detection(
                format: .ooxml, protection: .userPassword, removability: .removable,
                algorithm:
                    "AES-\(descriptor.keyBits) (ECMA-376 agile, \(descriptor.hashAlgorithm), "
                    + "\(descriptor.spinCount) spins)",
                detail: "Encrypted. Supply the password the document was protected with."
            )
        }

        // An unencrypted OOXML package is an ordinary ZIP.
        let members = try ZipArchiveReader.readMembers(data)
        guard members["[Content_Types].xml"] != nil else {
            return Detection(
                format: .unknown, protection: .unknown, removability: .unsupported,
                detail: "Not an Office Open XML package."
            )
        }
        for (name, contents) in members where name.hasSuffix("settings.xml") {
            guard let text = String(data: contents, encoding: .utf8) else { continue }
            if text.contains("documentProtection") {
                return Detection(
                    format: .ooxml, protection: .ownerRestrictions, removability: .refused,
                    detail: """
                        Marked read-only with documentProtection. The content is not \
                        encrypted, so removing that flag is a bypass rather than \
                        decryption -- this tool does not do it.
                        """
                )
            }
        }
        return Detection(
            format: .ooxml, protection: .none, removability: .notProtected,
            detail: "Not encrypted. \(members.count) part(s)."
        )
    }

    public func remove(_ data: Data, password: String) throws -> Data {
        guard CFBReader.isCFB(data) else {
            let detection = try detect(data)
            throw FprError.policyRefused(
                detection.protection == .ownerRestrictions
                    ? detection.detail
                    : "This document is not encrypted; there is nothing to remove."
            )
        }
        let container = try CFBReader(data)
        let descriptor = try readDescriptor(container)

        let base = iteratedHash(password: password, salt: descriptor.passwordSalt, spinCount: descriptor.spinCount)
        let keyLength = descriptor.keyBits / 8

        // Verify before doing anything else: a wrong password stops here.
        let verifierInputKey = derive(base, Self.verifierInputBlockKey, length: keyLength)
        let verifierValueKey = derive(base, Self.verifierValueBlockKey, length: keyLength)
        let verifierInput = try Crypto.aesCBCDecrypt(
            descriptor.encryptedVerifierHashInput, key: verifierInputKey, iv: descriptor.passwordSalt
        )
        let expectedHash = try Crypto.aesCBCDecrypt(
            descriptor.encryptedVerifierHashValue, key: verifierValueKey, iv: descriptor.passwordSalt
        )
        let actualHash = Crypto.sha512(verifierInput.prefix(16))
        guard Crypto.constantTimeEquals(
            Data(actualHash.prefix(64)), Data(expectedHash.prefix(64))
        ) else {
            throw FprError.wrongPassword
        }

        let keyValueKey = derive(base, Self.keyValueBlockKey, length: keyLength)
        let secretKey = try Crypto.aesCBCDecrypt(
            descriptor.encryptedKeyValue, key: keyValueKey, iv: descriptor.passwordSalt
        ).prefix(keyLength)

        let encryptedPackage = try container.stream(named: "EncryptedPackage")
        return try decryptPackage(
            encryptedPackage, secretKey: Data(secretKey), keyDataSalt: descriptor.keyDataSalt,
            blockSize: descriptor.keyDataBlockSize
        )
    }

    private func decryptPackage(
        _ package: Data, secretKey: Data, keyDataSalt: Data, blockSize: Int
    ) throws -> Data {
        guard package.count >= 8 else {
            throw FprError.corruptFile("EncryptedPackage stream is too short")
        }
        var reader = ByteReader(package)
        let declaredLength = Int(try reader.u64())
        var output = Data()
        output.reserveCapacity(declaredLength)

        var segment: UInt32 = 0
        while reader.remaining > 0 {
            let take = min(Self.segmentLength, reader.remaining)
            // Each segment gets its own IV, derived from the salt and its index.
            var salted = keyDataSalt
            salted.append(contentsOf: [
                UInt8(segment & 0xFF), UInt8((segment >> 8) & 0xFF),
                UInt8((segment >> 16) & 0xFF), UInt8((segment >> 24) & 0xFF),
            ])
            let iv = Crypto.sha512(salted).prefix(blockSize)
            let chunk = try reader.bytes(take - (take % 16))
            if take % 16 != 0 { _ = try? reader.bytes(take % 16) }
            output.append(try Crypto.aesCBCDecrypt(chunk, key: secretKey, iv: Data(iv)))
            segment += 1
        }

        guard declaredLength <= output.count else {
            throw FprError.corruptFile(
                "declared package length \(declaredLength) exceeds \(output.count) decrypted bytes"
            )
        }
        return output.prefix(declaredLength)
    }

    /// H0 = SHA512(salt || UTF16LE(password)); Hn = SHA512(LE32(n) || Hn-1).
    private func iteratedHash(password: String, salt: Data, spinCount: Int) -> Data {
        var hash = Crypto.sha512(salt + Data(Array(password.utf16).flatMap {
            [UInt8($0 & 0xFF), UInt8($0 >> 8)]
        }))
        for index in 0..<spinCount {
            var block = Data([
                UInt8(index & 0xFF), UInt8((index >> 8) & 0xFF),
                UInt8((index >> 16) & 0xFF), UInt8((index >> 24) & 0xFF),
            ])
            block.append(hash)
            hash = Crypto.sha512(block)
        }
        return hash
    }

    private func derive(_ hash: Data, _ blockKey: Data, length: Int) -> Data {
        Data(Crypto.sha512(hash + blockKey).prefix(length))
    }

    private func readDescriptor(_ container: CFBReader) throws -> AgileDescriptor {
        let stream = try container.stream(named: "EncryptionInfo")
        guard stream.count > 8 else {
            throw FprError.corruptFile("EncryptionInfo stream is too short")
        }
        var header = ByteReader(stream)
        let major = try header.u16()
        let minor = try header.u16()
        guard major == 4, minor == 4 else {
            throw FprError.unsupportedFormat(
                """
                This document uses ECMA-376 \(major).\(minor) encryption. Only agile \
                encryption (4.4) is supported.
                """
            )
        }
        _ = try header.u32()  // reserved flags
        let xml = stream.dropFirst(8)

        let parser = AgileDescriptorParser()
        guard let descriptor = parser.parse(Data(xml)) else {
            throw FprError.corruptFile("EncryptionInfo descriptor could not be parsed")
        }
        return descriptor
    }
}

/// Pulls the two attribute-only elements out of the agile descriptor.
private final class AgileDescriptorParser: NSObject, XMLParserDelegate {
    private var descriptor = OOXMLAdapter.AgileDescriptor()
    private var sawKeyData = false
    private var sawEncryptedKey = false

    func parse(_ data: Data) -> OOXMLAdapter.AgileDescriptor? {
        let parser = XMLParser(data: data)
        parser.delegate = self
        guard parser.parse(), sawKeyData, sawEncryptedKey else { return nil }
        return descriptor
    }

    func parser(
        _ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
        qualifiedName: String?, attributes: [String: String]
    ) {
        let local = elementName.split(separator: ":").last.map(String.init) ?? elementName
        func base64(_ key: String) -> Data {
            attributes[key].flatMap { Data(base64Encoded: $0) } ?? Data()
        }
        switch local {
        case "keyData":
            sawKeyData = true
            descriptor.keyDataSalt = base64("saltValue")
            descriptor.keyDataBlockSize = attributes["blockSize"].flatMap(Int.init) ?? 16
            descriptor.cipherAlgorithm = attributes["cipherAlgorithm"] ?? "AES"
        case "encryptedKey":
            sawEncryptedKey = true
            descriptor.spinCount = attributes["spinCount"].flatMap(Int.init) ?? 100_000
            descriptor.passwordSalt = base64("saltValue")
            descriptor.keyBits = attributes["keyBits"].flatMap(Int.init) ?? 256
            descriptor.hashAlgorithm = attributes["hashAlgorithm"] ?? "SHA512"
            descriptor.encryptedVerifierHashInput = base64("encryptedVerifierHashInput")
            descriptor.encryptedVerifierHashValue = base64("encryptedVerifierHashValue")
            descriptor.encryptedKeyValue = base64("encryptedKeyValue")
        default:
            break
        }
    }
}
