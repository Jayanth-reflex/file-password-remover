package dev.jayanth.fpr

/**
 * What kind of protection a file carries.
 *
 * Mirrors `fpr.types.Protection` and the Swift `Protection`. The distinction
 * between encryption and restriction flags is the whole point of the tool:
 * decrypting with the password you were given is not the same act as clearing
 * flags you were never given a password for.
 */
enum class Protection(val wire: String) {
    NONE("none"),
    USER_PASSWORD("user-password"),
    OWNER_RESTRICTIONS("owner-restrictions"),
    BOTH("user-password+owner-restrictions"),
    DRM("drm"),
    UNKNOWN("unknown"),
}

enum class Removability(val wire: String) {
    REMOVABLE("removable"),
    NOT_PROTECTED("not-protected"),
    REFUSED("refused"),
    UNSUPPORTED("unsupported"),
}

enum class FormatId(val wire: String) {
    PDF("pdf"),
    OOXML("ooxml"),
    ZIP("zip"),
    SEVEN_ZIP("7z"),
    LEGACY_OFFICE("legacy-office"),
    UNKNOWN("unknown"),
}

data class Detection(
    val format: FormatId,
    val protection: Protection,
    val removability: Removability,
    val algorithm: String? = null,
    val detail: String = "",
)

/**
 * Every failure this library reports, carrying the CLI's exit code so all three
 * implementations agree on what went wrong.
 */
sealed class FprException(message: String, val exitCode: Int) : Exception(message) {
    class WrongPassword :
        FprException("That password did not open the file.", 3)

    class PasswordRequired :
        FprException("This file needs a password.", 4)

    class UnsupportedFormat(detail: String) : FprException(detail, 5)

    class CorruptFile(detail: String) : FprException(detail, 6)

    class PolicyRefused(detail: String) : FprException(detail, 10)

    class InternalError(detail: String) : FprException(detail, 70)
}
