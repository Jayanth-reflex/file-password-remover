package dev.jayanth.fpr.app

import android.app.Application
import dev.jayanth.fpr.PdfBackends

/** Binds the Android PDF backend before anything can ask for one. */
class FprApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        PdfBackends.register(AndroidPdfBackend(this))
    }
}
