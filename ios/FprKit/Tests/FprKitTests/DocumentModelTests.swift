import XCTest
@testable import FprKit

/// Covers the pipeline the app actually runs: load a file from disk, inspect
/// it, supply a password, write a verified output file.
@MainActor
final class DocumentModelTests: XCTestCase {
    private func waitForStage(
        _ model: DocumentModel, timeout: TimeInterval = 10,
        until predicate: @escaping (DocumentModel.Stage) -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate(model.stage) { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTFail("timed out in stage \(model.stage)")
    }

    func testInspectsAnEncryptedFileAndReportsItAsRemovable() throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()

        model.load(try corpus.url("pdf-aes-256-r6-user"))

        guard case .inspected(let detection) = model.stage else {
            return XCTFail("expected .inspected, got \(model.stage)")
        }
        XCTAssertEqual(detection.protection, .userPassword)
        XCTAssertTrue(model.needsPassword)
    }

    func testWritesAVerifiedUnprotectedFileAndForgetsThePassword() async throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-aes256"))
        model.password = corpus.correctPassword

        model.removeProtection()
        try await waitForStage(model) { if case .done = $0 { return true }; return false }

        guard case .done(let url, let detection) = model.stage else {
            return XCTFail("expected .done, got \(model.stage)")
        }
        XCTAssertEqual(detection.protection, .none)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))

        // The output must genuinely open without a password.
        let written = try Data(contentsOf: url)
        XCTAssertEqual(try Engine().detect(written).protection, .none)

        // Content must survive.
        let expected = try corpus.members("zip-aes256")
        let recovered = try ZipArchiveReader.readMembers(written)
        XCTAssertEqual(Set(recovered.keys), Set(expected.keys))

        // The password must not still be sitting in the model.
        XCTAssertTrue(model.password.isEmpty, "password was retained after use")
    }

    func testAWrongPasswordFailsWithAnActionableMessageAndNoOutput() async throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-aes256"))
        model.password = corpus.wrongPassword

        model.removeProtection()
        try await waitForStage(model) { if case .failed = $0 { return true }; return false }

        guard case .failed(let message) = model.stage else {
            return XCTFail("expected .failed, got \(model.stage)")
        }
        XCTAssertTrue(
            message.lowercased().contains("password"),
            "message should name the problem, got: \(message)"
        )
    }

    func testRefusesAnOwnerRestrictedFileRatherThanStrippingFlags() async throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("pdf-owner-restrictions"))

        guard case .inspected(let detection) = model.stage else {
            return XCTFail("expected .inspected, got \(model.stage)")
        }
        XCTAssertEqual(detection.removability, .refused)
        XCTAssertFalse(model.needsPassword, "a refused file must not prompt for a password")
    }
}

@MainActor
final class ProtectModelTests: XCTestCase {
    private func waitForStage(
        _ model: DocumentModel, timeout: TimeInterval = 10,
        until predicate: @escaping (DocumentModel.Stage) -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate(model.stage) { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTFail("timed out in stage \(model.stage)")
    }

    func testAnUnprotectedFileOffersToBeProtected() throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()

        model.load(try corpus.url("pdf-plain"))

        XCTAssertEqual(model.available, .protectIt)
        XCTAssertFalse(model.needsPassword, "an unprotected file must not ask for a password to open")
    }

    func testAProtectedFileOffersToBeOpened() throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()

        model.load(try corpus.url("pdf-aes-256-r6-user"))

        XCTAssertEqual(model.available, .remove)
    }

    /// The generated password must come back out, or the file is destroyed.
    func testAGeneratedPasswordIsReturnedAndOpensTheFile() async throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-plain"))

        model.protectFile(generatePassword: true)
        try await waitForStage(model) { if case .protected = $0 { return true }; return false }

        guard case .protected(let url, let detection, let generated) = model.stage else {
            return XCTFail("expected .protected, got \(model.stage)")
        }
        XCTAssertEqual(detection.protection, .userPassword)
        let password = try XCTUnwrap(generated, "the generated password was not handed back")

        let written = try Data(contentsOf: url)
        XCTAssertEqual(try Engine().detect(written).protection, .userPassword)
        // And it is genuinely the password that opens it.
        XCTAssertEqual(
            try Engine().detect(try Engine().remove(written, password: password)).protection, .none
        )
    }

    func testAChosenPasswordIsNotHandedBack() async throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-plain"))
        model.password = "a-password-i-chose"
        model.confirmation = "a-password-i-chose"

        model.protectFile(generatePassword: false)
        try await waitForStage(model) { if case .protected = $0 { return true }; return false }

        guard case .protected(_, _, let generated) = model.stage else {
            return XCTFail("expected .protected, got \(model.stage)")
        }
        XCTAssertNil(generated, "a password the user chose is theirs; it must not be echoed")
        XCTAssertTrue(model.password.isEmpty, "the password was retained after use")
        XCTAssertTrue(model.confirmation.isEmpty, "the confirmation was retained after use")
    }

    /// Behind a mask, one wrong key locks the file with a password nobody
    /// knows -- and this tool will not crack it back open. The CLI asks twice
    /// for that reason; so does the app.
    func testAMismatchedConfirmationWritesNothing() async throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-plain"))
        model.password = "a-password-i-chose"
        model.confirmation = "a-password-i-chsoe"

        XCTAssertFalse(model.canProtect(generatePassword: false))
        model.protectFile(generatePassword: false)
        try await Task.sleep(nanoseconds: 300_000_000)

        guard case .inspected = model.stage else {
            return XCTFail("a mismatched password was acted on: \(model.stage)")
        }
    }

    func testAnEmptyChosenPasswordCannotProtect() throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-plain"))
        XCTAssertFalse(model.canProtect(generatePassword: false))
        XCTAssertTrue(model.canProtect(generatePassword: true))
    }

    func testLoadingAnotherFileClearsTheConfirmation() throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()
        model.load(try corpus.url("zip-plain"))
        model.confirmation = "left over"
        model.load(try corpus.url("pdf-plain"))
        XCTAssertTrue(model.confirmation.isEmpty)
    }

    func testAFormatThatCannotBeProtectedDoesNotOfferIt() throws {
        let corpus = try VectorCorpus.load()
        let model = DocumentModel()

        model.load(try corpus.url("ooxml-docx-plain"))

        XCTAssertEqual(model.available, .nothing)
    }
}
