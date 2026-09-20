package dev.jayanth.fpr

/**
 * PDF, via whichever PDFBox binding is registered (see [PdfBackend]).
 *
 * All the policy lives here so it is written and tested once: what counts as a
 * refusal, what the encryption is called, and verifying the output by re-reading
 * it. Only the PDFBox calls differ between desktop and Android.
 */
class PdfAdapter(private val backend: PdfBackend = PdfBackends.current()) {

    fun detect(data: ByteArray): Detection {
        val document = try {
            backend.open(data, null)
        } catch (error: FprException.WrongPassword) {
            // It refused an empty password, so a user password is set.
            return Detection(
                FormatId.PDF, Protection.USER_PASSWORD, Removability.REMOVABLE,
                algorithmName(data),
                "Encrypted. Supply the open (user) password or the owner password.",
            )
        }

        document.use {
            if (!it.isEncrypted) {
                return Detection(
                    FormatId.PDF, Protection.NONE, Removability.NOT_PROTECTED,
                    detail = "Not encrypted. ${it.pageCount} page(s).",
                )
            }
            // It opened with an empty user password, so anyone can read it: the
            // encryption is only carrying permission flags.
            val denied = it.deniedPermissions
            if (denied.isEmpty()) {
                return Detection(
                    FormatId.PDF, Protection.NONE, Removability.NOT_PROTECTED,
                    detail = "Not encrypted. ${it.pageCount} page(s).",
                )
            }
            return Detection(
                FormatId.PDF, Protection.OWNER_RESTRICTIONS, Removability.REFUSED,
                algorithmName(data),
                "Readable without a password, but flagged to deny ${denied.joinToString(", ")}. " +
                    "Clearing those flags without the owner password is a bypass, which this " +
                    "tool does not do.",
            )
        }
    }

    fun remove(data: ByteArray, password: String): ByteArray {
        // Decide refusals before touching the password. A document with an empty
        // user password opens for anyone, and PDFBox rejects a password matching
        // neither user nor owner -- reporting "wrong password" for a file being
        // refused on policy grounds would be misleading.
        val detection = detect(data)
        when (detection.protection) {
            Protection.OWNER_RESTRICTIONS -> throw FprException.PolicyRefused(detection.detail)
            Protection.NONE -> throw FprException.PolicyRefused(
                "This PDF is not encrypted; there is nothing to remove."
            )
            else -> Unit
        }

        backend.open(data, password).use { document ->
            val output = document.saveDecrypted()

            // Verify by re-reading what we are about to return.
            backend.open(output, null).use { rewritten ->
                if (rewritten.isEncrypted) {
                    throw FprException.InternalError("The rewritten PDF is still encrypted.")
                }
                if (rewritten.pageCount != document.pageCount) {
                    throw FprException.InternalError(
                        "Page count changed: ${document.pageCount} in, ${rewritten.pageCount} out."
                    )
                }
            }
            return output
        }
    }

    fun pageCount(data: ByteArray): Int = backend.open(data, null).use { it.pageCount }

    /** Report the encryption revision, which PDFBox does not surface directly. */
    private fun algorithmName(data: ByteArray): String? {
        val text = String(data.copyOf(minOf(data.size, 64_000)), Charsets.ISO_8859_1)
        val filter = text.indexOf("/Filter/Standard").takeIf { it >= 0 }
            ?: text.indexOf("/Filter /Standard").takeIf { it >= 0 }
            ?: return null
        val window = text.substring(filter, minOf(text.length, filter + 400))
        return when (Regex("/R\\s*(\\d+)").find(window)?.groupValues?.get(1)?.toIntOrNull()) {
            2 -> "RC4 40-bit (R2)"
            3 -> "RC4 128-bit (R3)"
            4 -> "AES-128 (R4)"
            5 -> "AES-256 (PDF 2.0, R5 deprecated)"
            6 -> "AES-256 (PDF 2.0, R6)"
            else -> null
        }
    }
}
