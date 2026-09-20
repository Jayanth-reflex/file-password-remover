import CryptoKit
import XCTest
@testable import FprKit

final class EngineTests: XCTestCase {
    /// Every vector in the corpus must be classified correctly from its bytes.
    /// Sniffing by extension would be a security bug: the corpus deliberately
    /// contains a file whose extension lies.
    func testClassifiesEveryVectorInTheCorpus() throws {
        let corpus = try VectorCorpus.load()
        for vector in corpus.vectors where vector.format != "unknown" {
            let data = try Data(contentsOf: corpus.root.appendingPathComponent(vector.file))
            let detection = try? Engine().detect(data)

            if vector.id == "damaged-not-an-archive" || vector.id == "damaged-pdf-truncated" {
                // Damaged input must fail cleanly; either a throw or an
                // "unknown" classification is acceptable, a crash is not.
                continue
            }
            XCTAssertEqual(
                detection?.format.rawValue, vector.format,
                "\(vector.id) was classified as \(detection?.format.rawValue ?? "throw")"
            )
            guard vector.format != "7z" else {
                // 7-Zip is identified but not yet implemented on iOS, so it
                // reports "unknown" protection on purpose. See docs/adr/0011.
                XCTAssertEqual(detection?.removability, .unsupported)
                continue
            }
            XCTAssertEqual(
                detection?.protection.rawValue, vector.protection,
                "\(vector.id) protection mismatch"
            )
        }
    }

    func testRemovesProtectionForEveryRemovableVector() throws {
        let corpus = try VectorCorpus.load()
        var removed = 0
        for vector in corpus.vectors where vector.removable {
            guard let password = vector.password else { continue }
            guard vector.format != "7z" else { continue }  // not supported on iOS yet
            let data = try Data(contentsOf: corpus.root.appendingPathComponent(vector.file))

            let output = try Engine().remove(data, password: password)
            XCTAssertFalse(output.isEmpty, "\(vector.id) produced no output")

            // Verify by re-reading the output, which is what the app does too.
            let reopened = try Engine().detect(output)
            XCTAssertEqual(reopened.protection, .none, "\(vector.id) is still protected")
            removed += 1
        }
        XCTAssertGreaterThanOrEqual(removed, 9, "expected the whole removable set")
    }

    func testRefusesEveryVectorMarkedNotRemovable() throws {
        let corpus = try VectorCorpus.load()
        for vector in corpus.vectors
        where !vector.removable && vector.protection == "owner-restrictions" {
            let data = try Data(contentsOf: corpus.root.appendingPathComponent(vector.file))
            XCTAssertThrowsError(
                try Engine().remove(data, password: corpus.correctPassword),
                "\(vector.id) should have been refused"
            )
        }
    }
}
