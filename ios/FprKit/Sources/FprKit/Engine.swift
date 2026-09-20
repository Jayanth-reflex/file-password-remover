import Foundation

/// Picks the adapter for a file and runs it.
///
/// The format is decided by looking at the bytes, never by the extension: the
/// test corpus deliberately includes a file named `.zip` that is not one, and
/// trusting the name there would be a security bug rather than a cosmetic one.
public struct Engine: Sendable {
    public init() {}

    public enum Format: Sendable {
        case pdf, ooxml, zip, sevenZip, legacyOffice
    }

    public func detect(_ data: Data) throws -> Detection {
        switch try sniff(data) {
        case .pdf: return try PDFAdapter().detect(data)
        case .ooxml: return try OOXMLAdapter().detect(data)
        case .zip: return try ZipAdapter().detect(data)
        case .legacyOffice: return try LegacyOfficeAdapter().detect(data)
        case .sevenZip:
            return Detection(
                format: .sevenZip, protection: .unknown, removability: .unsupported,
                detail: """
                    7-Zip archives are not supported in this app. Use the desktop \
                    command-line tool, which handles them.
                    """
            )
        }
    }

    public func remove(_ data: Data, password: String) throws -> Data {
        switch try sniff(data) {
        case .pdf: return try PDFAdapter().remove(data, password: password)
        case .ooxml: return try OOXMLAdapter().remove(data, password: password)
        case .zip: return try ZipAdapter().remove(data, password: password)
        case .legacyOffice: return try LegacyOfficeAdapter().remove(data, password: password)
        case .sevenZip:
            throw FprError.unsupportedFormat(
                "7-Zip archives are not supported in this app; use the desktop command-line tool."
            )
        }
    }

    /// Identify the container from its magic bytes.
    func sniff(_ data: Data) throws -> Format {
        guard data.count >= 8 else {
            throw FprError.corruptFile("file is too small to identify")
        }
        if data.prefix(5) == Data("%PDF-".utf8) { return .pdf }
        if data.prefix(6) == Data([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) { return .sevenZip }

        if CFBReader.isCFB(data) {
            // A CFB container is either an encrypted OOXML document or a
            // Word/Excel 97-2003 binary. The EncryptionInfo stream tells them apart.
            let container = try CFBReader(data)
            return container.hasStream(named: "EncryptionInfo") ? .ooxml : .legacyOffice
        }

        if data.prefix(2) == Data("PK".utf8) {
            // Both OOXML packages and plain ZIPs are ZIP files. OOXML declares
            // itself with a content-type map at a fixed name.
            if let members = try? ZipArchiveReader.readMembers(data),
               members["[Content_Types].xml"] != nil {
                return .ooxml
            }
            return .zip
        }

        throw FprError.unsupportedFormat("unrecognised file format")
    }
}
