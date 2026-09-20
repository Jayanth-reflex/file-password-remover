import CryptoKit
import XCTest
@testable import FprKit

final class PasswordGeneratorTests: XCTestCase {
    func testGeneratedPasswordIsGroupedForTranscription() throws {
        let password = PasswordGenerator.generate()
        XCTAssertNotNil(
            password.range(of: #"^[a-z0-9]{4}(-[a-z0-9]{4}){4}$"#, options: .regularExpression),
            "unexpected shape: \(password)"
        )
    }

    /// A password nobody can read back off a screen is not usable, and an
    /// unusable password is one the user replaces with something weak.
    func testAlphabetExcludesCharactersPeopleConfuse() {
        for confusable in "ilo01" {
            XCTAssertFalse(
                PasswordGenerator.alphabet.contains(confusable),
                "\(confusable) is easy to misread"
            )
        }
    }

    func testTwoGeneratedPasswordsDiffer() {
        XCTAssertNotEqual(PasswordGenerator.generate(), PasswordGenerator.generate())
    }

    func testEntropyIsFarPastGuessable() {
        XCTAssertGreaterThanOrEqual(PasswordGenerator.entropyBits, 90)
    }
}

final class ProtectTests: XCTestCase {
    /// The contract in one test: lock it, and the password must open it again
    /// with the content intact.
    private func assertRoundTrip(
        vectorID: String, corpus: VectorCorpus, file: StaticString = #filePath, line: UInt = #line
    ) throws {
        let original = try corpus.data(vectorID)
        let password = PasswordGenerator.generate()

        let locked = try Engine().protect(original, password: password)

        let detection = try Engine().detect(locked)
        XCTAssertEqual(
            detection.protection, .userPassword,
            "\(vectorID) was not actually protected", file: file, line: line
        )

        let reopened = try Engine().remove(locked, password: password)
        XCTAssertEqual(
            try Engine().detect(reopened).protection, .none,
            "\(vectorID) did not unlock", file: file, line: line
        )
    }

    func testProtectsAZipAndOpensItAgain() throws {
        try assertRoundTrip(vectorID: "zip-plain", corpus: try VectorCorpus.load())
    }

    func testProtectsAPdfAndOpensItAgain() throws {
        try assertRoundTrip(vectorID: "pdf-plain", corpus: try VectorCorpus.load())
    }

    func testZipContentSurvivesBeingLockedAndUnlocked() throws {
        let corpus = try VectorCorpus.load()
        let expected = try ZipArchiveReader.readMembers(try corpus.data("zip-plain"))
        let password = PasswordGenerator.generate()

        let locked = try Engine().protect(try corpus.data("zip-plain"), password: password)
        let recovered = try ZipArchiveReader.readMembers(
            try Engine().remove(locked, password: password)
        )

        XCTAssertEqual(Set(recovered.keys), Set(expected.keys))
        for (name, bytes) in expected {
            XCTAssertEqual(
                SHA256.hash(data: try XCTUnwrap(recovered[name])).map { String(format: "%02x", $0) }.joined(),
                SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
                "content of \(name) changed"
            )
        }
    }

    func testProtectingAnAlreadyEncryptedFileIsRefused() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try Engine().protect(try corpus.data("zip-aes256"), password: "irrelevant")
        ) { error in
            guard case .policyRefused = error as? FprError else {
                return XCTFail("expected policyRefused, got \(error)")
            }
        }
    }

    func testAnUnsupportedFormatSaysSo() throws {
        let corpus = try VectorCorpus.load()
        XCTAssertThrowsError(
            try Engine().protect(try corpus.data("ooxml-docx-plain"), password: "irrelevant")
        ) { error in
            guard case .unsupportedFormat = error as? FprError else {
                return XCTFail("expected unsupportedFormat, got \(error)")
            }
        }
    }
}

/// Writes what this implementation produces to disk, so another one can try to
/// open it.
///
/// A round trip through the same code proves only that it agrees with itself,
/// which is worth very little for an encryptor. `scripts/check_interop.py`
/// opens these with the Python implementation, and CI runs it straight after
/// this suite.
final class InteropArtifactTests: XCTestCase {
    static let password = "interop-fixed-password"

    private func write(_ data: Data, named name: String) throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("build/interop")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try data.write(to: root.appendingPathComponent(name))
    }

    func testWritesAProtectedZipForTheOtherImplementationToOpen() throws {
        let corpus = try VectorCorpus.load()
        let locked = try Engine().protect(
            try corpus.data("zip-plain"), password: Self.password
        )
        try write(locked, named: "swift-protected.zip")
    }

    func testWritesAProtectedPdfForTheOtherImplementationToOpen() throws {
        let corpus = try VectorCorpus.load()
        let locked = try Engine().protect(
            try corpus.data("pdf-plain"), password: Self.password
        )
        try write(locked, named: "swift-protected.pdf")
    }
}
