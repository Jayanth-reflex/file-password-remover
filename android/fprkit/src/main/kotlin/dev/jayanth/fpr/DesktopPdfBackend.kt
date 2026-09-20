package dev.jayanth.fpr

import java.io.ByteArrayOutputStream
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException

/**
 * Desktop PDFBox binding, used by the JVM tests and anywhere the engine runs
 * outside Android. See [PdfBackend] for why Android needs a different one.
 */
class DesktopPdfBackend : PdfBackend {

    private class Handle(private val document: PDDocument) : PdfBackend.Document {
        override val isEncrypted: Boolean get() = document.isEncrypted
        override val pageCount: Int get() = document.numberOfPages

        override val deniedPermissions: List<String>
            get() = document.currentAccessPermission.let { permissions ->
                buildList {
                    if (!permissions.canPrint()) add("printing")
                    if (!permissions.canExtractContent()) add("copying")
                    if (!permissions.canExtractForAccessibility()) add("accessibility")
                    if (!permissions.canModify()) add("editing")
                }
            }

        override fun saveDecrypted(): ByteArray {
            document.isAllSecurityToBeRemoved = true
            return ByteArrayOutputStream().also { document.save(it) }.toByteArray()
        }

        override fun close() = document.close()
    }

    override fun open(data: ByteArray, password: String?): PdfBackend.Document = try {
        Handle(Loader.loadPDF(data, password ?: ""))
    } catch (error: InvalidPasswordException) {
        throw FprException.WrongPassword()
    } catch (error: FprException) {
        throw error
    } catch (error: Exception) {
        throw FprException.CorruptFile("This file could not be opened as a PDF.")
    }
}
