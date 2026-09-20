import Foundation
import PDFKit

/// PDF, via PDFKit's implementation of the standard security handler.
///
/// PDFKit decrypts a document once the correct password is supplied and writes
/// it back out unencrypted. It does not, and this adapter does not, attempt to
/// open a document whose password is not known.
public struct PDFAdapter: Sendable {
    public init() {}

    public func detect(_ data: Data) throws -> Detection {
        guard let document = PDFDocument(data: data) else {
            throw FprError.corruptFile("This file could not be opened as a PDF.")
        }

        if document.isLocked {
            // Encrypted with a user password: without it there is no content.
            return Detection(
                format: .pdf, protection: .userPassword, removability: .removable,
                algorithm: algorithmName(data),
                detail: "Encrypted. Supply the open (user) password or the owner password."
            )
        }

        if document.isEncrypted {
            // It opened with an empty user password, so anyone can read it. The
            // encryption is only carrying permission flags.
            let denied = deniedPermissions(document)
            guard denied.isEmpty else {
                return Detection(
                    format: .pdf, protection: .ownerRestrictions, removability: .refused,
                    algorithm: algorithmName(data),
                    detail: """
                        Readable without a password, but flagged to deny \
                        \(denied.joined(separator: ", ")). Clearing those flags without the \
                        owner password is a bypass, which this tool does not do.
                        """
                )
            }
        }

        return Detection(
            format: .pdf, protection: .none, removability: .notProtected,
            detail: "Not encrypted. \(document.pageCount) page(s)."
        )
    }

    public func remove(_ data: Data, password: String) throws -> Data {
        guard let document = PDFDocument(data: data) else {
            throw FprError.corruptFile("This file could not be opened as a PDF.")
        }

        if document.isLocked {
            guard document.unlock(withPassword: password) else {
                throw FprError.wrongPassword
            }
        } else {
            let detection = try detect(data)
            switch detection.protection {
            case .ownerRestrictions:
                throw FprError.policyRefused(detection.detail)
            case .none:
                throw FprError.policyRefused("This PDF is not encrypted; there is nothing to remove.")
            default:
                break
            }
        }

        // PDFKit writes the original security handler back out for the older
        // revisions (R2-R4), so a straight re-save can still be encrypted. Take
        // it only when re-reading proves it came out clean.
        if let output = document.dataRepresentation(), !output.isEmpty,
           let rewritten = PDFDocument(data: output),
           !rewritten.isLocked, !rewritten.isEncrypted,
           rewritten.pageCount == document.pageCount {
            return output
        }

        let rebuilt = try rebuildWithoutEncryption(document)
        guard let output = rebuilt.dataRepresentation(), !output.isEmpty else {
            throw FprError.internalError("PDFKit produced no output for this document.")
        }
        guard let rewritten = PDFDocument(data: output), !rewritten.isLocked, !rewritten.isEncrypted
        else {
            throw FprError.internalError("The rewritten PDF is still encrypted.")
        }
        guard rewritten.pageCount == document.pageCount else {
            throw FprError.internalError(
                "Page count changed: \(document.pageCount) in, \(rewritten.pageCount) out."
            )
        }
        return output
    }

    /// Copy the pages into a fresh document, which carries no security handler.
    ///
    /// Document attributes and the outline are carried across explicitly.
    /// Anything PDFKit does not expose at page level -- embedded files, form
    /// field values, structure tags -- does not survive this path, which is why
    /// it is only used when a plain re-save comes back still encrypted.
    private func rebuildWithoutEncryption(_ document: PDFDocument) throws -> PDFDocument {
        let rebuilt = PDFDocument()
        for index in 0..<document.pageCount {
            guard let page = document.page(at: index) else {
                throw FprError.corruptFile("page \(index + 1) could not be read")
            }
            guard let copy = page.copy() as? PDFPage else {
                throw FprError.internalError("page \(index + 1) could not be copied")
            }
            rebuilt.insert(copy, at: index)
        }
        if let attributes = document.documentAttributes {
            rebuilt.documentAttributes = attributes
        }
        if let outline = document.outlineRoot {
            rebuilt.outlineRoot = outline
        }
        return rebuilt
    }

    public func pageCount(_ data: Data) throws -> Int {
        guard let document = PDFDocument(data: data) else {
            throw FprError.corruptFile("This file could not be opened as a PDF.")
        }
        return document.pageCount
    }

    private func deniedPermissions(_ document: PDFDocument) -> [String] {
        var denied: [String] = []
        if !document.allowsPrinting { denied.append("printing") }
        if !document.allowsCopying { denied.append("copying") }
        if !document.allowsContentAccessibility { denied.append("accessibility") }
        if !document.allowsDocumentChanges { denied.append("editing") }
        return denied
    }

    /// Read the encryption revision straight out of the trailer dictionary.
    /// PDFKit does not expose it, and the user deserves to be told whether
    /// their document is RC4-40 or AES-256.
    private func algorithmName(_ data: Data) -> String? {
        guard let text = String(data: data.prefix(64_000), encoding: .isoLatin1) else { return nil }
        guard let range = text.range(of: "/Filter/Standard") ?? text.range(of: "/Filter /Standard")
        else { return nil }
        let window = text[range.lowerBound...].prefix(400)
        func value(_ key: String) -> Int? {
            guard let keyRange = window.range(of: key) else { return nil }
            let digits = window[keyRange.upperBound...].prefix(6)
                .drop(while: { $0 == " " })
                .prefix(while: { $0.isNumber })
            return Int(digits)
        }
        switch (value("/R"), value("/V")) {
        case (2, _): return "RC4 40-bit (R2)"
        case (3, _): return "RC4 128-bit (R3)"
        case (4, _): return "AES-128 (R4)"
        case (5, _): return "AES-256 (PDF 2.0, R5 deprecated)"
        case (6, _): return "AES-256 (PDF 2.0, R6)"
        default: return nil
        }
    }
}
