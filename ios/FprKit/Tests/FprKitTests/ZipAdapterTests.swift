import XCTest
@testable import FprKit

final class ZipAdapterTests: XCTestCase {
    func testDetectsAes256ZipAsEncryptedWithAUserPassword() throws {
        let corpus = try VectorCorpus.load()
        let data = try Data(contentsOf: corpus.url("zip-aes256"))

        let detection = try ZipAdapter().detect(data)

        XCTAssertEqual(detection.protection, .userPassword)
        XCTAssertEqual(detection.removability, .removable)
    }
}
