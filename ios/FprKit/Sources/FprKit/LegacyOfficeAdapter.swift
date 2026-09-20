import Foundation

/// Word/Excel 97-2003 binary documents (`.doc`, `.xls`).
///
/// Detection only. These use RC4 or RC4+CryptoAPI inside a CFB container, and
/// this port does not implement that decryption -- so it says so, rather than
/// reporting a success it cannot deliver. Users are pointed at the desktop CLI.
public struct LegacyOfficeAdapter: Sendable {
    public init() {}

    private static let wordIdentifier: UInt16 = 0xA5EC
    private static let encryptedFlag: UInt16 = 0x0100

    public func detect(_ data: Data) throws -> Detection {
        guard CFBReader.isCFB(data) else {
            throw FprError.corruptFile("not a Word/Excel 97-2003 document")
        }
        let container = try CFBReader(data)

        if container.hasStream(named: "WordDocument") {
            let stream = try container.stream(named: "WordDocument")
            guard stream.count >= 12 else {
                throw FprError.corruptFile("File Information Block is truncated")
            }
            var reader = ByteReader(stream)
            let identifier = try reader.u16()
            guard identifier == Self.wordIdentifier else {
                throw FprError.corruptFile(
                    "unexpected wIdent 0x\(String(identifier, radix: 16)) in WordDocument stream"
                )
            }
            try reader.seek(0x0A)
            let flags = try reader.u16()
            guard flags & Self.encryptedFlag != 0 else {
                return Detection(
                    format: .legacyOffice, protection: .none, removability: .notProtected,
                    detail: "Word 97-2003 document, not encrypted."
                )
            }
            return Detection(
                format: .legacyOffice, protection: .userPassword, removability: .unsupported,
                algorithm: "RC4 or RC4+CryptoAPI ([MS-DOC])",
                detail: """
                    Encrypted Word 97-2003 document. This app cannot decrypt the legacy \
                    RC4 schemes; use the desktop command-line tool for this file.
                    """
            )
        }

        if container.hasStream(named: "Workbook") || container.hasStream(named: "Book") {
            return Detection(
                format: .legacyOffice, protection: .unknown, removability: .unsupported,
                detail: """
                    Excel 97-2003 workbook. Encryption state is recorded in BIFF records \
                    this app does not parse; use the desktop command-line tool.
                    """
            )
        }

        throw FprError.unsupportedFormat("compound file with no recognised Office streams")
    }

    public func remove(_ data: Data, password: String) throws -> Data {
        _ = password
        let detection = try? detect(data)
        throw FprError.unsupportedFormat(
            detection?.detail
                ?? "Legacy Office decryption is not available in this app; use the desktop CLI."
        )
    }
}
