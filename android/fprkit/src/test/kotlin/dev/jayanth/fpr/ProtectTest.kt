package dev.jayanth.fpr

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PasswordGeneratorTest {

    @Test
    fun `generated password is grouped for transcription`() {
        val password = PasswordGenerator.generate()
        assertTrue(password, Regex("[a-z0-9]{4}(-[a-z0-9]{4}){4}").matches(password))
    }

    /** A password nobody can read back off a screen is not usable. */
    @Test
    fun `alphabet excludes characters people confuse`() {
        for (confusable in "ilo01") {
            assertTrue("$confusable is easy to misread", !PasswordGenerator.ALPHABET.contains(confusable))
        }
    }

    @Test
    fun `two generated passwords differ`() {
        assertNotEquals(PasswordGenerator.generate(), PasswordGenerator.generate())
    }

    @Test
    fun `entropy is far past guessable`() {
        assertTrue(PasswordGenerator.entropyBits >= 90)
    }
}

class ProtectTest {

    /** Lock it, and the password must open it again with the content intact. */
    private fun assertRoundTrip(id: String) {
        val corpus = VectorCorpus.load()
        val password = PasswordGenerator.generate()

        val locked = Engine().protect(corpus.bytes(id), password)

        assertEquals("$id was not protected", Protection.USER_PASSWORD, Engine().detect(locked).protection)
        val reopened = Engine().remove(locked, password)
        assertEquals("$id did not unlock", Protection.NONE, Engine().detect(reopened).protection)
    }

    @Test fun `protects a zip and opens it again`() = assertRoundTrip("zip-plain")
    @Test fun `protects a pdf and opens it again`() = assertRoundTrip("pdf-plain")

    @Test
    fun `zip content survives being locked and unlocked`() {
        val corpus = VectorCorpus.load()
        val expected = ZipArchive.readMembers(corpus.bytes("zip-plain"))
        val password = PasswordGenerator.generate()

        val locked = Engine().protect(corpus.bytes("zip-plain"), password)
        val recovered = ZipArchive.readMembers(Engine().remove(locked, password))

        assertEquals(expected.keys, recovered.keys)
        expected.forEach { (name, bytes) ->
            assertEquals("content of $name changed", sha256Hex(bytes), sha256Hex(recovered.getValue(name)))
        }
    }

    @Test
    fun `protecting an already encrypted file is refused`() {
        val corpus = VectorCorpus.load()
        try {
            Engine().protect(corpus.bytes("zip-aes256"), "irrelevant")
            fail("expected PolicyRefused")
        } catch (expected: FprException.PolicyRefused) {
            assertTrue(expected.message!!.isNotEmpty())
        }
    }

    @Test
    fun `an unsupported format says so`() {
        val corpus = VectorCorpus.load()
        try {
            Engine().protect(corpus.bytes("ooxml-docx-plain"), "irrelevant")
            fail("expected UnsupportedFormat")
        } catch (expected: FprException.UnsupportedFormat) {
            assertEquals(5, expected.exitCode)
        }
    }
}

/**
 * Writes what this implementation produces, so another one can try to open it.
 *
 * A round trip through the same code proves only that it agrees with itself,
 * which is worth very little for an encryptor. `scripts/check_interop.py`
 * opens these with the Python implementation, and CI runs it after this suite.
 */
class InteropArtifactTest {
    private val password = "interop-fixed-password"

    private fun write(data: ByteArray, name: String) {
        val root = File(System.getProperty("fpr.interop") ?: "build/interop")
        root.mkdirs()
        File(root, name).writeBytes(data)
    }

    @Test
    fun `writes a protected zip for the other implementation to open`() {
        write(Engine().protect(VectorCorpus.load().bytes("zip-plain"), password), "kotlin-protected.zip")
    }

    @Test
    fun `writes a protected pdf for the other implementation to open`() {
        write(Engine().protect(VectorCorpus.load().bytes("pdf-plain"), password), "kotlin-protected.pdf")
    }
}
