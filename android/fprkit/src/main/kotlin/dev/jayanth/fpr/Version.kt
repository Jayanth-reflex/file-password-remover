package dev.jayanth.fpr

/**
 * What this build of the library calls itself.
 *
 * The engine, the CLI and the two apps are one product with one version, and a
 * bug report that names a version has to be traceable to the code that produced
 * it. `tests/unit/test_version_consistency.py` checks this constant against
 * `fpr.__version__` and against `versionName` in the app's Gradle build, so the
 * number shown in the app cannot drift away from the number in the release
 * notes.
 */
object FprKit {

    /** Matches `fpr.__version__` and the app's `versionName`. */
    const val VERSION = "1.1.0"
}
