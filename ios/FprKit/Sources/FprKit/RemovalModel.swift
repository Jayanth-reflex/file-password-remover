import Foundation
import SwiftUI

/// Drives one file through detect -> remove -> verify.
///
/// The password lives in this object only for the duration of the call and is
/// cleared immediately afterwards. It is never written to a log, never put in
/// a URL, and never persisted.
@MainActor
public final class RemovalModel: ObservableObject {
    public enum Stage: Equatable {
        case empty
        case inspected(Detection)
        case working
        case done(URL, Detection)
        case failed(String)
    }

    @Published public private(set) var stage: Stage = .empty
    @Published public private(set) var fileName: String = ""
    @Published public var password: String = ""

    private var sourceData: Data?

    public init() {}

    public var needsPassword: Bool {
        if case .inspected(let detection) = stage { return detection.removability == .removable }
        return false
    }

    public func load(_ url: URL) {
        stage = .empty
        password = ""
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

                let destination = try Self.write(output, basedOn: await self.fileName)
                await MainActor.run { self.stage = .done(destination, verified) }
            } catch {
                await MainActor.run { self.stage = .failed(Self.describe(error)) }
            }
        }
    }

    public func reset() {
        sourceData = nil
        fileName = ""
        password = ""
        stage = .empty
    }

    /// Write to a private temp directory, never over the original.
    private nonisolated static func write(_ data: Data, basedOn name: String) throws -> URL {
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("fpr-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let target = directory.appendingPathComponent(
            ext.isEmpty ? "\(base)-unprotected" : "\(base)-unprotected.\(ext)"
        )
        try data.write(to: target, options: [.atomic, .completeFileProtection])
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
