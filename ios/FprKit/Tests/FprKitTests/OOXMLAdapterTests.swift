import XCTest
@testable import FprKit

final class OOXMLAdapterTests: XCTestCase {
    func testDetectsAnAgileEncryptedDocumentAsNeedingAPassword() throws {
        let corpus = try VectorCorpus.load()
        let detection = try OOXMLAdapter().detect(try corpus.data("ooxml-docx-agile"))

        XCTAssertEqual(detection.protection, .userPassword)
        XCTAssertEqual(detection.removability, .removable)
    }

    /// The decrypted payload must be a real OOXML package -- a ZIP whose first
    /// part is the content-type map. Anything less means we produced rubbish.
    private func assertDecryptsToAPackage(_ id: String, corpus: VectorCorpus) throws {
        let output = try OOXMLAdapter().remove(try corpus.data(id), password: corpus.correctPassword)
        let members = try ZipArchiveReader.readMembers(output)
        XCTAssertNotNil(members["[Content_Types].xml"], "\(id) did not decrypt to an OOXML package")
    }

    func testRemovesEncryptionFromDocx() throws {
        try assertDecryptsToAPackage("ooxml-docx-agile", corpus: try VectorCorpus.load())
    }

    func testRemovesEncryptionFromXlsx() throws {
        try assertDecryptsToAPackage("ooxml-xlsx-agile", corpus: try VectorCorpus.load())
    }

    func testRemovesEncryptionFromPptx() throws {
        try assertDecryptsToAPackage("ooxml-pptx-agile", corpus: try VectorCorpus.load())
    }

    func testRejectsTheWrongPassword() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try OOXMLAdapter().remove(try corpus.data("ooxml-docx-agile"), password: corpus.wrongPassword)
        ) { error in
            XCTAssertEqual(error as? FprError, .wrongPassword)
        }
    }

    func testRefusesDocumentProtectionWhichIsNotEncryption() throws {
        let corpus = try VectorCorpus.load()
        let detection = try OOXMLAdapter().detect(try corpus.data("ooxml-docx-restricted"))

        XCTAssertEqual(detection.protection, .ownerRestrictions)
        XCTAssertEqual(detection.removability, .refused)
    }

    func testReportsAnUnencryptedPackageAsNotProtected() throws {
        let corpus = try VectorCorpus.load()
        let detection = try OOXMLAdapter().detect(try corpus.data("ooxml-docx-plain"))

        XCTAssertEqual(detection.protection, .none)
    }
}
