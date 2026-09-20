package dev.jayanth.fpr

import java.io.ByteArrayOutputStream
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException

/**
 * PDF, via PDFBox's implementation of the standard security handler.
 *
 * PDFBox decrypts once the correct password is supplied and can then save the
 * document with its security removed. It does not, and this adapter does not,
 * try to open a document whose password is unknown.
 */
class PdfAdapter {

    fun detect(data: ByteArray): Detection {
        val document = try {
            Loader.loadPDF(data)
        } catch (error: InvalidPasswordException) {
            // It refused an empty password, so there is a user password.
            return Detection(
                FormatId.PDF, Protection.USER_PASSWORD, Removability.REMOVABLE,
                algorithmName(data),
                "Encrypted. Supply the open (user) password or the owner password.",
            )
        } catch (error: Exception) {
            throw FprException.CorruptFile("This file could not be opened as a PDF.")
        }

        document.use {
            if (!it.isEncrypted) {
                return Detection(
                    FormatId.PDF, Protection.NONE, Removability.NOT_PROTECTED,
                    detail = "Not encrypted. ${it.numberOfPages} page(s).",
                )
            }
            // It opened with an empty user password, so anyone can read it and
            // the encryption is only carrying permission flags.
            val denied = deniedPermissions(it)
            if (denied.isEmpty()) {
                return Detection(
                    FormatId.PDF, Protection.NONE, Removability.NOT_PROTECTED,
                    detail = "Not encrypted. ${it.numberOfPages} page(s).",
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
        // user password opens for anyone, and PDFBox rejects a password that
        // matches neither user nor owner -- which would report "wrong password"
        // for a file we are refusing on policy grounds anyway.
        val detection = detect(data)
        when (detection.protection) {
            Protection.OWNER_RESTRICTIONS -> throw FprException.PolicyRefused(detection.detail)
            Protection.NONE -> throw FprException.PolicyRefused(
                "This PDF is not encrypted; there is nothing to remove."
            )
            else -> Unit
        }

        val document = try {
            Loader.loadPDF(data, password)
        } catch (error: InvalidPasswordException) {
            throw FprException.WrongPassword()
        } catch (error: Exception) {
            throw FprException.CorruptFile("This file could not be opened as a PDF.")
        }

        document.use {
            it.isAllSecurityToBeRemoved = true
            val output = ByteArrayOutputStream()
            it.save(output)
            val bytes = output.toByteArray()

            // Verify by re-reading what we are about to return.
            Loader.loadPDF(bytes).use { rewritten ->
                if (rewritten.isEncrypted) {
                    throw FprException.InternalError("The rewritten PDF is still encrypted.")
                }
                if (rewritten.numberOfPages != it.numberOfPages) {
                    throw FprException.InternalError(
                        "Page count changed: ${it.numberOfPages} in, ${rewritten.numberOfPages} out."
                    )
                }
            }
            return bytes
        }
    }

    fun pageCount(data: ByteArray): Int = Loader.loadPDF(data).use { it.numberOfPages }

    private fun deniedPermissions(document: PDDocument): List<String> {
        val permissions = document.currentAccessPermission
        return buildList {
            if (!permissions.canPrint()) add("printing")
            if (!permissions.canExtractContent()) add("copying")
            if (!permissions.canExtractForAccessibility()) add("accessibility")
            if (!permissions.canModify()) add("editing")
        }
    }

    /** Report the encryption revision, which PDFBox does not surface directly. */
    private fun algorithmName(data: ByteArray): String? {
        val text = String(data.copyOf(minOf(data.size, 64_000)), Charsets.ISO_8859_1)
        val filter = text.indexOf("/Filter/Standard").takeIf { it >= 0 }
            ?: text.indexOf("/Filter /Standard").takeIf { it >= 0 }
            ?: return null
        val window = text.substring(filter, minOf(text.length, filter + 400))
        val revision = Regex("/R\\s*(\\d+)").find(window)?.groupValues?.get(1)?.toIntOrNull()
        return when (revision) {
            2 -> "RC4 40-bit (R2)"
            3 -> "RC4 128-bit (R3)"
            4 -> "AES-128 (R4)"
            5 -> "AES-256 (PDF 2.0, R5 deprecated)"
            6 -> "AES-256 (PDF 2.0, R6)"
            else -> null
        }
    }
}
