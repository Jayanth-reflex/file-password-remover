import Foundation

/// What this build of the library calls itself.
///
/// The engine, the CLI and the two apps are one product with one version, and a
/// bug report that names a version has to be traceable to the code that
/// produced it. `tests/unit/test_version_consistency.py` checks this constant
/// against `fpr.__version__` and against the Xcode build setting, so the number
/// shown in the app cannot drift away from the number in the release notes.
public enum FprKit {

    /// Matches `fpr.__version__` and `MARKETING_VERSION` in the Xcode project.
    public static let version = "1.1.0"
}
