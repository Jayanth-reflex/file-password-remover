import XCTest
@testable import FprKit

/// Covers the pipeline the app actually runs: load a file from disk, inspect
/// it, supply a password, write a verified output file.
@MainActor
final class RemovalModelTests: XCTestCase {
    private func waitForStage(
        _ model: RemovalModel, timeout: TimeInterval = 10,
        until predicate: @escaping (RemovalModel.Stage) -> Bool
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
        let model = RemovalModel()

        model.load(try corpus.url("pdf-aes-256-r6-user"))

        guard case .inspected(let detection) = model.stage else {
            return XCTFail("expected .inspected, got \(model.stage)")
        }
        XCTAssertEqual(detection.protection, .userPassword)
        XCTAssertTrue(model.needsPassword)
    }

    func testWritesAVerifiedUnprotectedFileAndForgetsThePassword() async throws {
        let corpus = try VectorCorpus.load()
        let model = RemovalModel()
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
        let model = RemovalModel()
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
        let model = RemovalModel()
        model.load(try corpus.url("pdf-owner-restrictions"))

        guard case .inspected(let detection) = model.stage else {
            return XCTFail("expected .inspected, got \(model.stage)")
        }
        XCTAssertEqual(detection.removability, .refused)
        XCTAssertFalse(model.needsPassword, "a refused file must not prompt for a password")
    }
}
