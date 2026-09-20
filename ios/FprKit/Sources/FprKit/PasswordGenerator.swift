import Foundation
import Security

/// Generates a password for a file about to be protected.
///
/// The only place in this library that *creates* a secret rather than consuming
/// one, and security-critical for an unusual reason: this tool refuses to crack
/// passwords, so a generated password is the only copy that will ever exist. If
/// the user loses it the file is gone.
///
/// Mirrors `fpr.passwords` in the Python implementation, down to the alphabet,
/// so a password generated on one platform reads the same on another.
public enum PasswordGenerator {

    /// Lowercase letters and digits, minus the pairs that get confused in most
    /// faces: i/l/1 and o/0. 31 symbols, about 4.95 bits each.
    public static let alphabet = Array("abcdefghjkmnpqrstuvwxyz23456789")

    public static let groups = 5
    public static let groupSize = 4

    /// Entropy of the default shape. Hyphens are separators for the eye and
    /// carry none of it.
    public static var entropyBits: Double {
        Double(groups * groupSize) * log2(Double(alphabet.count))
    }

    /// A new random password, grouped with hyphens for transcription.
    ///
    /// Randomness comes from the system CSPRNG through `SecRandomCopyBytes`.
    /// Rejection sampling keeps the distribution uniform: taking a raw byte
    /// modulo 31 would quietly favour the first few symbols.
    public static func generate() -> String {
        var chunks: [String] = []
        for _ in 0..<groups {
            var chunk = ""
            while chunk.count < groupSize {
                chunk.append(alphabet[Int(uniformByte(below: UInt8(alphabet.count)))])
            }
            chunks.append(chunk)
        }
        return chunks.joined(separator: "-")
    }

    private static func uniformByte(below bound: UInt8) -> UInt8 {
        // The largest multiple of `bound` that fits in a byte; anything at or
        // above it is discarded rather than folded back in.
        let limit = UInt8(256 - (256 % Int(bound)))
        while true {
            var byte: UInt8 = 0
            let status = withUnsafeMutableBytes(of: &byte) { buffer in
                SecRandomCopyBytes(kSecRandomDefault, 1, buffer.baseAddress!)
            }
            precondition(status == errSecSuccess, "the system random number generator failed")
            if byte < limit { return byte % bound }
        }
    }
}
