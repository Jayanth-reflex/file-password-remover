import Foundation

/// What kind of protection a file carries.
///
/// Mirrors `fpr.types.Protection`. The distinction is the whole point of the
/// tool: decrypting with the owner's password is not the same act as clearing
/// restriction flags you were never given the password for.
public enum Protection: String, Sendable, Equatable {
    case none = "none"
    case userPassword = "user-password"
    case ownerRestrictions = "owner-restrictions"
    case both = "user-password+owner-restrictions"
    case drm = "drm"
    case unknown = "unknown"
}

/// Whether this tool will act on the detected protection.
public enum Removability: String, Sendable, Equatable {
    case removable
    case notProtected = "not-protected"
    case refused
    case unsupported
}

public enum FormatID: String, Sendable, Equatable {
    case pdf, ooxml, zip, sevenZip = "7z", legacyOffice = "legacy-office", unknown
}

public struct Detection: Sendable, Equatable {
    public let format: FormatID
    public let protection: Protection
    public let removability: Removability
    public let algorithm: String?
    public let detail: String

    public init(
        format: FormatID,
        protection: Protection,
        removability: Removability,
        algorithm: String? = nil,
        detail: String = ""
    ) {
        self.format = format
        self.protection = protection
        self.removability = removability
        self.algorithm = algorithm
        self.detail = detail
    }
}

/// Every failure this library can report, mapped onto the CLI's exit codes so
/// the three implementations agree on what went wrong.
public enum FprError: Error, Equatable {
    case wrongPassword
    case passwordRequired
    case unsupportedFormat(String)
    case corruptFile(String)
    case policyRefused(String)
    case internalError(String)

    /// The CLI exit code this failure corresponds to.
    public var exitCode: Int32 {
        switch self {
        case .wrongPassword: return 3
        case .passwordRequired: return 4
        case .unsupportedFormat: return 5
        case .corruptFile: return 6
        case .policyRefused: return 10
        case .internalError: return 70
        }
    }
}
