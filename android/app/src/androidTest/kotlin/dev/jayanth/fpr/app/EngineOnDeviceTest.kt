package dev.jayanth.fpr.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.jayanth.fpr.Engine
import dev.jayanth.fpr.FprException
import dev.jayanth.fpr.Protection
import dev.jayanth.fpr.ZipArchive
import dev.jayanth.fpr.sha256Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs the engine on a real Android runtime.
 *
 * The JVM unit tests prove the algorithms; this proves they still work on ART,
 * where the crypto providers, the XML parser and the zip implementation are
 * Android's rather than the JDK's. That difference is exactly the kind of thing
 * that is easy to assume and wrong.
 *
 * Vectors are pushed to the device by the CI job before this runs.
 */
@RunWith(AndroidJUnit4::class)
class EngineOnDeviceTest {

    private val corpus = DeviceCorpus.load()

    @Test
    fun removesAesZipEncryptionAndPreservesContent() {
        val expected = corpus.members("zip-aes256")

        val output = Engine().remove(corpus.bytes("zip-aes256"), corpus.correctPassword)

        val recovered = ZipArchive.readMembers(output)
        assertEquals(expected.keys, recovered.keys)
        expected.forEach { (name, member) ->
            assertEquals("content of $name", member.sha256, sha256Hex(recovered.getValue(name)))
        }
    }

    @Test
    fun removesAgileOoxmlEncryption() {
        val output = Engine().remove(corpus.bytes("ooxml-docx-agile"), corpus.correctPassword)
        assertTrue(ZipArchive.readMembers(output).containsKey("[Content_Types].xml"))
    }

    @Test
    fun removesPdfEncryption() {
        val output = Engine().remove(corpus.bytes("pdf-aes-256-r6-user"), corpus.correctPassword)
        assertEquals(Protection.NONE, Engine().detect(output).protection)
    }

    @Test
    fun removesSevenZipEncryption() {
        val output = Engine().remove(corpus.bytes("7z-encrypted-header"), corpus.correctPassword)
        assertEquals(Protection.NONE, Engine().detect(output).protection)
    }

    @Test
    fun rejectsTheWrongPassword() {
        try {
            Engine().remove(corpus.bytes("zip-aes256"), corpus.wrongPassword)
            fail("expected WrongPassword")
        } catch (expected: FprException.WrongPassword) {
            assertEquals(3, expected.exitCode)
        }
    }

    @Test
    fun refusesOwnerRestrictionsRatherThanStrippingThem() {
        try {
            Engine().remove(corpus.bytes("pdf-owner-restrictions"), corpus.correctPassword)
            fail("expected PolicyRefused")
        } catch (expected: FprException.PolicyRefused) {
            assertTrue(expected.message!!.isNotEmpty())
        }
    }

    /**
     * The app declares no INTERNET permission, so the platform itself blocks
     * network access. This asserts that rather than trusting the manifest.
     */
    @Test
    fun theAppCannotReachTheNetworkAtAll() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val permission = context.packageManager.checkPermission(
            android.Manifest.permission.INTERNET, context.packageName,
        )
        assertEquals(
            "the app must not hold INTERNET permission",
            android.content.pm.PackageManager.PERMISSION_DENIED, permission,
        )
    }
}
