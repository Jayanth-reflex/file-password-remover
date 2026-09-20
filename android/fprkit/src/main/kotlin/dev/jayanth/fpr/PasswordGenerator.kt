package dev.jayanth.fpr

import java.security.SecureRandom
import kotlin.math.ln

/**
 * Generates a password for a file about to be protected.
 *
 * The only place in this library that *creates* a secret rather than consuming
 * one, and security-critical for an unusual reason: this tool refuses to crack
 * passwords, so a generated password is the only copy that will ever exist. If
 * the user loses it, the file is gone.
 *
 * Mirrors `fpr.passwords` in the Python implementation, down to the alphabet,
 * so a password generated on one platform reads the same on another.
 */
object PasswordGenerator {

    /**
     * Lowercase letters and digits, minus the pairs that get confused in most
     * faces: i/l/1 and o/0. 31 symbols, about 4.95 bits each.
     */
    const val ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"

    const val GROUPS = 5
    const val GROUP_SIZE = 4

    /** Entropy of the default shape. Hyphens separate for the eye and add none. */
    val entropyBits: Double
        get() = GROUPS * GROUP_SIZE * (ln(ALPHABET.length.toDouble()) / ln(2.0))

    private val random = SecureRandom()

    /**
     * A new random password, grouped with hyphens for transcription.
     *
     * `SecureRandom.nextInt(bound)` is already uniform over the range, so no
     * rejection sampling is needed here -- unlike the Swift port, which works
     * from raw bytes.
     */
    fun generate(): String = (1..GROUPS).joinToString("-") {
        buildString {
            repeat(GROUP_SIZE) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
        }
    }
}
