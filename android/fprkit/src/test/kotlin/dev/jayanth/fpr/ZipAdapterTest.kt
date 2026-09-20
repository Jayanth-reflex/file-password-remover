package dev.jayanth.fpr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ZipAdapterTest {
    @Test
    fun `detects an AES-256 zip as encrypted with a user password`() {
        val corpus = VectorCorpus.load()

        val detection = ZipAdapter().detect(corpus.bytes("zip-aes256"))

        assertEquals(Protection.USER_PASSWORD, detection.protection)
        assertEquals(Removability.REMOVABLE, detection.removability)
    }

    @Test
    fun `removes AES-256 encryption preserving every byte of content`() {
        val corpus = VectorCorpus.load()
        val expected = corpus.members("zip-aes256")

        val output = ZipAdapter().remove(corpus.bytes("zip-aes256"), corpus.correctPassword)

        val recovered = ZipArchive.readMembers(output)
        assertEquals(expected.keys, recovered.keys)
        expected.forEach { (name, member) ->
            assertEquals("content of $name", member.sha256, sha256Hex(recovered.getValue(name)))
        }
        assertTrue(
            "output still has encrypted entries",
            ZipArchive.readCentralDirectory(output).none { it.isEncrypted },
        )
    }
}
