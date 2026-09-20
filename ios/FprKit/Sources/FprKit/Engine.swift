import CryptoKit
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

    /// Write a copy of `data` protected with `password`.
    ///
    /// Only PDF and ZIP can be protected. Every other format refuses rather
    /// than quietly handing back a copy with no encryption on it, which would
    /// be the most dangerous possible failure for this operation.
    public func protect(_ data: Data, password: String) throws -> Data {
        switch try sniff(data) {
        case .pdf: return try PDFAdapter().protect(data, password: password)
        case .zip: return try ZipAdapter().protect(data, password: password)
        case .ooxml:
            throw FprError.unsupportedFormat(
                "Adding protection to Office documents is not supported yet. This app can "
                + "remove it, but not add it."
            )
        case .sevenZip:
            throw FprError.unsupportedFormat(
                "7-Zip archives are not supported in this app at all."
            )
        case .legacyOffice:
            throw FprError.unsupportedFormat(
                "Adding protection to Word/Excel 97-2003 files is not supported."
            )
        }
    }

    /// Evidence about a file, gathered by reading it back.
    ///
    /// This is what fills the hallmark row: every entry is something actually
    /// read out of the bytes, never a claim carried over from the operation
    /// that produced them.
    ///
    /// Pass `password` for a file that was just protected. Opening it is the
    /// only way to say anything about what is inside, and "it is encrypted" on
    /// its own is a thin claim -- an empty encrypted file would satisfy it.
    public func evidence(_ data: Data, password: String? = nil) throws -> [String: String] {
        switch try sniff(data) {
        case .pdf:
            return try pdfEvidence(data, password: password)
        case .zip, .ooxml:
            return try zipEvidence(data, password: password)
        case .sevenZip, .legacyOffice:
            return [:]
        }
    }

    private func pdfEvidence(_ data: Data, password: String?) throws -> [String: String] {
        let detection = try PDFAdapter().detect(data)
        let encrypted = detection.protection != .none
        var marks = ["encrypted": encrypted ? "true" : "false"]
        if let algorithm = detection.algorithm { marks["algorithm"] = algorithm }

        if !encrypted {
            marks["pages"] = String(try PDFAdapter().pageCount(data))
            return marks
        }
        guard let password else { return marks }
        // Opened with the password we just set, so the page count is a fact
        // about the protected file rather than about the one it came from.
        let opened = try PDFAdapter().remove(data, password: password)
        marks["opens"] = "true"
        marks["pages"] = String(try PDFAdapter().pageCount(opened))
        return marks
    }

    private func zipEvidence(_ data: Data, password: String?) throws -> [String: String] {
        let entries = try ZipStructure.readCentralDirectory(data)
        let encrypted = entries.contains { $0.isEncrypted }
        var marks = [
            "encrypted": encrypted ? "true" : "false",
            "entries": String(entries.count),
        ]

        let readable: Data?
        if encrypted {
            guard let password else { return marks }
            readable = try? ZipAdapter().remove(data, password: password)
            if readable != nil { marks["opens"] = "true" }
        } else {
            readable = data
        }
        guard let readable, let members = try? ZipArchiveReader.readMembers(readable) else {
            return marks
        }
        // A digest over every member name and its contents, so a changed byte
        // anywhere shows up as a changed mark.
        var hasher = SHA256()
        for name in members.keys.sorted() {
            hasher.update(data: Data(name.utf8))
            hasher.update(data: members[name] ?? Data())
        }
        marks["digest"] = String(
            hasher.finalize().map { String(format: "%02x", $0) }.joined().prefix(16)
        )
        return marks
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
