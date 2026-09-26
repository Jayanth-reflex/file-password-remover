package dev.jayanth.fpr.app

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The app, driven the way a person drives it: choose a file, type, tap.
 *
 * The one thing replaced is the system file picker, which belongs to another
 * app and cannot be driven from here. Espresso-Intents answers the
 * ACTION_OPEN_DOCUMENT request with a real file, so everything from the
 * activity-result callback onward -- the view model, the engine, the output,
 * the screen -- is the code a user runs.
 */
@RunWith(AndroidJUnit4::class)
class DocumentScreenJourneyTest {

    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val corpus by lazy { DeviceCorpus.load() }
    private val timeout = 30_000L

    @Before
    fun startStubbingThePicker() = Intents.init()

    @After
    fun stopStubbingThePicker() = Intents.release()

    // ---------------------------------------------------------------- journeys

    @Test
    fun removingProtectionFromAPdf() {
        choose("locked.pdf", corpus.bytes("pdf-aes-256-r6-user"))
        type("password-field", corpus.correctPassword)
        tap("remove-button")

        waitFor("success")
        compose.onNodeWithText("Protection removed", substring = true).assertExists()
    }

    @Test
    fun removingProtectionFromAZip() {
        choose("archive.zip", corpus.bytes("zip-aes256"))
        type("password-field", corpus.correctPassword)
        tap("remove-button")
        waitFor("success")
    }

    @Test
    fun aWrongPasswordIsReportedAndTheRightOneThenWorks() {
        choose("locked.pdf", corpus.bytes("pdf-aes-256-r6-user"))
        type("password-field", corpus.wrongPassword)
        tap("remove-button")
        waitFor("error")

        tap("start-over")
        choose("locked.pdf", corpus.bytes("pdf-aes-256-r6-user"))
        type("password-field", corpus.correctPassword)
        tap("remove-button")
        waitFor("success")
    }

    @Test
    fun protectingWithAGeneratedPasswordShowsItOnce() {
        choose("plain.pdf", corpus.bytes("pdf-plain"))
        tap("protect-button")
        waitFor("generated-password")
    }

    /**
     * Behind a mask, one wrong key would lock the file with a password nobody
     * knows, and this app cannot recover it. The button stays disabled until
     * both fields agree.
     */
    @Test
    fun aChosenPasswordMustBeTypedTwice() {
        choose("plain.zip", corpus.bytes("zip-plain"))
        compose.onNodeWithText("Use my own").performScrollTo().performClick()

        type("new-password-field", "typed carefully")
        type("confirm-password-field", "typed carefuly")
        compose.onNodeWithTag("password-mismatch").assertExists()
        compose.onNodeWithTag("protect-button").performScrollTo().assertIsNotEnabled()

        compose.onNodeWithTag("confirm-password-field").performTextReplacement("typed carefully")
        compose.onNodeWithTag("protect-button").performScrollTo().assertIsEnabled()
        tap("protect-button")
        waitFor("success")
        // A password the user chose is theirs; it is never displayed back.
        assertFalse(exists("generated-password"))
    }

    @Test
    fun theVersionIsShown() {
        // Rendered as a caption, which is set in capitals.
        compose.onNodeWithText("Version ", substring = true, ignoreCase = true)
            .performScrollTo()
            .assertExists()
    }

    // ----------------------------------------------------------------- helpers

    /** Answer the next file-picker request with this file, then tap Choose. */
    private fun choose(name: String, bytes: ByteArray) {
        val context = compose.activity
        val file = File(File(context.cacheDir, "e2e").apply { mkdirs() }, name)
        file.writeBytes(bytes)
        intending(hasAction(Intent.ACTION_OPEN_DOCUMENT)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(Uri.fromFile(file)))
        )
        tap("choose-file")
        waitFor("start-over")
    }

    private fun type(tag: String, text: String) {
        compose.onNodeWithTag(tag).performScrollTo().performTextInput(text)
    }

    private fun tap(tag: String) {
        compose.onNodeWithTag(tag).performScrollTo().performClick()
    }

    private fun exists(tag: String): Boolean =
        compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) {
        compose.waitUntil(timeout) { exists(tag) }
        assertTrue("$tag never appeared", exists(tag))
    }
}
