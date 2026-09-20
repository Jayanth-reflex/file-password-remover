import XCTest
@testable import FprKit

final class LegacyOfficeAdapterTests: XCTestCase {
    /// Word 97-2003 RC4/CryptoAPI decryption is not implemented, and saying so
    /// is the point of this test: detection must report the protection AND
    /// report that this tool cannot remove it, rather than claiming success.
    func testDetectsEncryptionButReportsItAsUnsupported() throws {
        let corpus = try VectorCorpus.load()
        let detection = try LegacyOfficeAdapter().detect(try corpus.data("legacy-doc-encrypted"))

        XCTAssertEqual(detection.format, .legacyOffice)
        XCTAssertEqual(detection.protection, .userPassword)
        XCTAssertEqual(detection.removability, .unsupported)
    }

    func testReportsAnUnencryptedLegacyDocumentAsNotProtected() throws {
        let corpus = try VectorCorpus.load()
        let detection = try LegacyOfficeAdapter().detect(try corpus.data("legacy-doc-plain"))

        XCTAssertEqual(detection.protection, .none)
    }

    func testRemoveAlwaysRefusesRatherThanPretending() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try LegacyOfficeAdapter().remove(
                try corpus.data("legacy-doc-encrypted"), password: corpus.correctPassword
            )
        ) { error in
            guard case .unsupportedFormat = error as? FprError else {
                return XCTFail("expected unsupportedFormat, got \(error)")
            }
        }
    }
}
