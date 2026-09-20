package dev.jayanth.fpr.app

import android.content.Context
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import com.tom_roush.pdfbox.pdmodel.PDDocument
import com.tom_roush.pdfbox.pdmodel.encryption.InvalidPasswordException
import dev.jayanth.fpr.FprException
import dev.jayanth.fpr.PdfBackend
import java.io.ByteArrayOutputStream

/**
 * PDFBox binding for Android.
 *
 * Desktop PDFBox fails on ART: `PDDocument`'s static initialiser resolves
 * `java.awt.Point`, which does not exist there. This uses the `pdfbox-android`
 * port, which has the same shape with a different package. All the policy stays
 * in the shared `PdfAdapter`.
 */
class AndroidPdfBackend(context: Context) : PdfBackend {

    init {
        // Loads the font and glyph-list resources the port needs from assets.
        PDFBoxResourceLoader.init(context.applicationContext)
    }

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
            document.setAllSecurityToBeRemoved(true)
            return ByteArrayOutputStream().also { document.save(it) }.toByteArray()
        }

        override fun close() = document.close()
    }

    override fun open(data: ByteArray, password: String?): PdfBackend.Document = try {
        Handle(PDDocument.load(data, password ?: ""))
    } catch (error: InvalidPasswordException) {
        throw FprException.WrongPassword()
    } catch (error: FprException) {
        throw error
    } catch (error: Exception) {
        throw FprException.CorruptFile("This file could not be opened as a PDF.")
    }
}
