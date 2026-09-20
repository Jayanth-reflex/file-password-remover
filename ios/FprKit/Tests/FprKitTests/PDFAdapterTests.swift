import XCTest
@testable import FprKit

final class PDFAdapterTests: XCTestCase {
    func testDetectsAnEncryptedPDFAsNeedingAUserPassword() throws {
        let corpus = try VectorCorpus.load()
        let detection = try PDFAdapter().detect(try corpus.data("pdf-aes-256-r6-user"))

        XCTAssertEqual(detection.protection, .userPassword)
        XCTAssertEqual(detection.removability, .removable)
    }

    func testDetectsOwnerRestrictionsAndRefusesToStripThem() throws {
        let corpus = try VectorCorpus.load()
        let data = try corpus.data("pdf-owner-restrictions")

        let detection = try PDFAdapter().detect(data)
        XCTAssertEqual(detection.protection, .ownerRestrictions)
        XCTAssertEqual(detection.removability, .refused)

        // Clearing these flags is a bypass: the content is already readable and
        // we were never given the owner password. This must stay a refusal.
        XCTAssertThrowsError(try PDFAdapter().remove(data, password: "")) { error in
            guard case .policyRefused = error as? FprError else {
                return XCTFail("expected policyRefused, got \(error)")
            }
        }
    }

    func testRemovesEncryptionAndKeepsEveryPage() throws {
        let corpus = try VectorCorpus.load()
        let expectedPages = try XCTUnwrap(corpus.vector("pdf-aes-256-r6-user").expect.pages)

        let output = try PDFAdapter().remove(
            try corpus.data("pdf-aes-256-r6-user"), password: corpus.correctPassword
        )

        let reopened = try PDFAdapter().detect(output)
        XCTAssertEqual(reopened.protection, .none, "output is still encrypted")
        XCTAssertEqual(try PDFAdapter().pageCount(output), expectedPages)
    }

    func testRejectsTheWrongPassword() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try PDFAdapter().remove(try corpus.data("pdf-aes-256-r6-user"), password: corpus.wrongPassword)
        ) { error in
            XCTAssertEqual(error as? FprError, .wrongPassword)
        }
    }

    func testReportsATruncatedPDFAsCorruptRatherThanCrashing() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try PDFAdapter().remove(try corpus.data("damaged-pdf-truncated"), password: corpus.correctPassword)
        )
    }
}
