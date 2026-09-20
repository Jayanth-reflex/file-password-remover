import Foundation
import SwiftUI

/// Drives one file through detect -> act -> verify, in either direction.
///
/// The password lives in this object only for the duration of the call and is
/// cleared immediately afterwards. It is never written to a log, never put in
/// a URL, and never persisted.
///
/// A *generated* password is the exception: it is held in `.protected` until
/// the user dismisses that screen, because it is the only copy that will ever
/// exist and this tool refuses to recover it.
@MainActor
public final class DocumentModel: ObservableObject {
    public enum Stage: Equatable {
        case empty
        case inspected(Detection)
        case working
        case done(URL, Detection)
        /// The generated password, if this tool made one, to be shown once.
        case protected(URL, Detection, String?)
        case failed(String)
    }

    /// What can be done with the file that is loaded.
    public enum Action: Equatable {
        case remove
        case protectIt
        case nothing
    }

    @Published public private(set) var stage: Stage = .empty
    @Published public private(set) var fileName: String = ""
    @Published public var password: String = ""

    /// Evidence from re-reading the file that was just written. Empty until
    /// something has actually been verified.
    @Published public private(set) var verification: [String: String] = [:]

    private var sourceData: Data?

    public init() {}

    public var needsPassword: Bool {
        available == .remove
    }

    /// Removing and protecting are the same gesture in opposite directions, so
    /// the file itself decides which one is on offer.
    public var available: Action {
        guard case .inspected(let detection) = stage else { return .nothing }
        if detection.removability == .removable { return .remove }
        if detection.protection == .none, Self.canProtect(detection.format) { return .protectIt }
        return .nothing
    }

    static func canProtect(_ format: FormatID) -> Bool {
        format == .pdf || format == .zip
    }

    public func load(_ url: URL) {
        stage = .empty
        password = ""
        // Evidence belongs to one run; it must never sit under a different file.
        verification = [:]
        // Files handed over by the document picker are security-scoped.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: url)
            sourceData = data
            fileName = url.lastPathComponent
            stage = .inspected(try Engine().detect(data))
        } catch {
            sourceData = nil
            stage = .failed(Self.describe(error))
        }
    }

    /// Protect the loaded file with the typed password, or a generated one.
    ///
    /// The file is written before the password is handed back, so a failure
    /// between the two cannot leave a locked file whose password was never
    /// shown. A password the *user* chose is not returned: it is already
    /// theirs, and echoing it would only put it somewhere new.
    public func protectFile(generatePassword: Bool) {
        guard let data = sourceData else { return }
        stage = .working
        let chosen = generatePassword ? PasswordGenerator.generate() : password
        password = ""

        Task.detached(priority: .userInitiated) {
            do {
                let output = try Engine().protect(data, password: chosen)

                let verified = try Engine().detect(output)
                guard verified.protection == .userPassword else {
                    throw FprError.internalError("The output file is not protected.")
                }

                let marks = (try? Engine().evidence(output, password: chosen)) ?? [:]
                let destination = try Self.write(
                    output, basedOn: await self.fileName, suffix: "-protected"
                )
                await MainActor.run {
                    self.verification = marks
                    self.stage = .protected(
                        destination, verified, generatePassword ? chosen : nil
                    )
                }
            } catch {
                await MainActor.run { self.stage = .failed(Self.describe(error)) }
            }
        }
    }

    public func removeProtection() {
        guard let data = sourceData else { return }
        stage = .working
        let secret = password
        // Drop our copy as soon as the work is queued.
        password = ""

        Task.detached(priority: .userInitiated) {
            do {
                let output = try Engine().remove(data, password: secret)

                // Verify by re-reading what we are about to hand back, rather
                // than trusting that the write succeeded.
                let verified = try Engine().detect(output)
                guard verified.protection == .none else {
                    throw FprError.internalError("The output file is still protected.")
                }

                let marks = (try? Engine().evidence(output)) ?? [:]
                let destination = try Self.write(
                    output, basedOn: await self.fileName, suffix: "-unprotected"
                )
                await MainActor.run {
                    self.verification = marks
                    self.stage = .done(destination, verified)
                }
            } catch {
                await MainActor.run { self.stage = .failed(Self.describe(error)) }
            }
        }
    }

    public func reset() {
        sourceData = nil
        fileName = ""
        password = ""
        verification = [:]
        stage = .empty
    }

    /// Write to a private temp directory, never over the original.
    private nonisolated static func write(
        _ data: Data, basedOn name: String, suffix: String
    ) throws -> URL {
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("fpr-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let target = directory.appendingPathComponent(
            ext.isEmpty ? "\(base)\(suffix)" : "\(base)\(suffix).\(ext)"
        )
        // File protection classes are an iOS facility; asking for one on macOS
        // fails outright, which is where this library's tests run.
        #if os(iOS)
        try data.write(to: target, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: target, options: [.atomic])
        #endif
        // Owner-only, on every platform. The directory above is already 0700,
        // but the file is what gets handed to a share sheet.
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        return target
    }

    public nonisolated static func describe(_ error: Error) -> String {
        guard let error = error as? FprError else { return error.localizedDescription }
        switch error {
        case .wrongPassword:
            return "That password did not open the file. Check it and try again."
        case .passwordRequired:
            return "This file needs a password."
        case .unsupportedFormat(let detail), .corruptFile(let detail),
             .policyRefused(let detail), .internalError(let detail):
            return detail
        }
    }
}
