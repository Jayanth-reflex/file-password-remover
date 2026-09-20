package dev.jayanth.fpr

/**
 * The small part of PDFBox that [PdfAdapter] actually needs.
 *
 * Desktop PDFBox cannot run on Android -- `PDDocument` touches `java.awt.Point`
 * in its static initialiser, so it fails with `NoClassDefFoundError` on ART.
 * The Android app therefore binds a different PDFBox build (the `pdfbox-android`
 * port), while all the policy -- what counts as a refusal, what the algorithm is
 * called, verifying the output -- stays here and is tested once.
 */
interface PdfBackend {

    interface Document : AutoCloseable {
        val isEncrypted: Boolean
        val pageCount: Int
        /** Permissions the document asks consumers to deny, e.g. "printing". */
        val deniedPermissions: List<String>
        /** Re-save with the security handler removed. */
        fun saveDecrypted(): ByteArray
    }

    /**
     * Open a document. Implementations throw [FprException.WrongPassword] when
     * the password does not open it, and [FprException.CorruptFile] when the
     * bytes are not a readable PDF.
     */
    fun open(data: ByteArray, password: String?): Document
}

/**
 * Which PDF backend is in use.
 *
 * The JVM build registers the desktop PDFBox binding automatically; the Android
 * app registers its own at startup. If nothing is registered, PDF support
 * reports itself unavailable rather than failing with a class-loading error
 * that means nothing to the person holding the phone.
 */
object PdfBackends {

    @Volatile
    private var backend: PdfBackend? = null

    fun register(value: PdfBackend) {
        backend = value
    }

    fun current(): PdfBackend = backend ?: autoRegister() ?: throw FprException.UnsupportedFormat(
        "PDF support is not available in this build."
    )

    /** Use the desktop PDFBox binding when it is on the classpath and usable. */
    private fun autoRegister(): PdfBackend? = try {
        val candidate = Class.forName("dev.jayanth.fpr.DesktopPdfBackend")
            .getDeclaredConstructor().newInstance() as PdfBackend
        // Touching PDDocument here surfaces the java.awt problem on Android now,
        // where it can be handled, rather than mid-decryption.
        Class.forName("org.apache.pdfbox.pdmodel.PDDocument")
        backend = candidate
        candidate
    } catch (error: Throwable) {
        null
    }
}
