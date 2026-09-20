import CryptoKit
import XCTest
@testable import FprKit

final class ZipRemovalTests: XCTestCase {
    /// Decrypting must reproduce the exact plaintext the Python generator put in.
    /// Digest equality is what makes this a real test rather than a smoke test.
    private func assertRoundTrip(
        vectorID: String, corpus: VectorCorpus, file: StaticString = #filePath, line: UInt = #line
    ) throws {
        let expected = try corpus.members(vectorID)
        let output = try ZipAdapter().remove(try corpus.data(vectorID), password: corpus.correctPassword)

        let recovered = try ZipArchiveReader.readMembers(output)
        XCTAssertEqual(
            Set(recovered.keys), Set(expected.keys),
            "member list changed for \(vectorID)", file: file, line: line
        )
        for (name, expectedMember) in expected {
            let bytes = try XCTUnwrap(recovered[name], "missing \(name)", file: file, line: line)
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(
                digest, expectedMember.sha256,
                "content of \(name) in \(vectorID) does not match", file: file, line: line
            )
        }

        let entries = try ZipStructure.readCentralDirectory(output)
        XCTAssertTrue(
            entries.allSatisfy { !$0.isEncrypted },
            "output still has encrypted entries", file: file, line: line
        )
    }

    func testRemovesAes256EncryptionPreservingEveryByteOfContent() throws {
        try assertRoundTrip(vectorID: "zip-aes256", corpus: try VectorCorpus.load())
    }

    func testRemovesAes128Encryption() throws {
        try assertRoundTrip(vectorID: "zip-aes128", corpus: try VectorCorpus.load())
    }

    func testRemovesAes192Encryption() throws {
        try assertRoundTrip(vectorID: "zip-aes192", corpus: try VectorCorpus.load())
    }

    func testRemovesLegacyZipCryptoEncryption() throws {
        try assertRoundTrip(vectorID: "zip-zipcrypto", corpus: try VectorCorpus.load())
    }

    func testRemovesEncryptionFromAMixedArchiveKeepingThePlainEntry() throws {
        try assertRoundTrip(vectorID: "zip-mixed", corpus: try VectorCorpus.load())
    }

    func testRefusesAnArchiveThatIsNotEncrypted() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try ZipAdapter().remove(try corpus.data("zip-plain"), password: corpus.correctPassword)
        ) { error in
            guard case .policyRefused = error as? FprError else {
                return XCTFail("expected policyRefused, got \(error)")
            }
        }
    }

    func testReportsAFileThatIsNotAZipAsCorruptRatherThanCrashing() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(try ZipAdapter().detect(try corpus.data("damaged-not-an-archive"))) { error in
            guard case .corruptFile = error as? FprError else {
                return XCTFail("expected corruptFile, got \(error)")
            }
        }
    }

    func testRejectsTheWrongPasswordWithoutProducingOutput() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try ZipAdapter().remove(try corpus.data("zip-aes256"), password: corpus.wrongPassword)
        ) { error in
            XCTAssertEqual(error as? FprError, .wrongPassword)
        }
    }
}
