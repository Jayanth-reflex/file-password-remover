package dev.jayanth.fpr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class EngineTest {

    /**
     * Every vector must be classified from its bytes. Sniffing by extension
     * would be a security bug: the corpus contains a file whose extension lies.
     */
    @Test
    fun `classifies every vector in the corpus`() {
        val corpus = VectorCorpus.load()
        for (vector in corpus.vectors) {
            if (vector.id.startsWith("damaged-")) continue
            val detection = Engine().detect(corpus.bytes(vector.id))
            assertEquals("${vector.id} format", vector.format, detection.format.wire)
            assertEquals("${vector.id} protection", vector.protection, detection.protection.wire)
        }
    }

    @Test
    fun `removes protection from every removable vector and verifies the output`() {
        val corpus = VectorCorpus.load()
        // Derived from the corpus rather than hardcoded: 7-Zip vectors are absent
        // when the optional py7zr extra is (ADR-0006), and this should adapt
        // rather than fail for the wrong reason.
        val expected = corpus.vectors.filter {
            it.removable && it.password != null && it.format != "legacy-office"
        }
        assertTrue("corpus has no removable vectors to check", expected.size >= 13)

        var removed = 0
        for (vector in expected) {
            val output = Engine().remove(corpus.bytes(vector.id), vector.password!!)
            assertTrue("${vector.id} produced no output", output.isNotEmpty())
            assertEquals(
                "${vector.id} is still protected",
                Protection.NONE, Engine().detect(output).protection,
            )
            removed += 1
        }
        assertEquals("expected the whole removable set", expected.size, removed)
    }

    @Test
    fun `refuses every vector marked not removable`() {
        val corpus = VectorCorpus.load()
        for (vector in corpus.vectors) {
            if (vector.removable || vector.protection != "owner-restrictions") continue
            try {
                Engine().remove(corpus.bytes(vector.id), corpus.correctPassword)
                fail("${vector.id} should have been refused")
            } catch (expected: FprException.PolicyRefused) {
                assertNotNull(expected.message)
            }
        }
    }

    @Test
    fun `reports a file whose extension lies as corrupt rather than trusting the name`() {
        val corpus = VectorCorpus.load()
        try {
            Engine().detect(corpus.bytes("damaged-not-an-archive"))
            fail("expected a failure for a file that is not an archive")
        } catch (expected: FprException) {
            assertTrue(expected is FprException.CorruptFile || expected is FprException.UnsupportedFormat)
        }
    }
}
