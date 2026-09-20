package dev.jayanth.fpr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ZipVariantTest {
    private fun assertRoundTrip(id: String) {
        val corpus = VectorCorpus.load()
        val expected = corpus.members(id)

        val output = ZipAdapter().remove(corpus.bytes(id), corpus.correctPassword)

        val recovered = ZipArchive.readMembers(output)
        assertEquals("$id member list", expected.keys, recovered.keys)
        expected.forEach { (name, member) ->
            assertEquals("$id content of $name", member.sha256, sha256Hex(recovered.getValue(name)))
        }
    }

    @Test fun `removes AES-128`() = assertRoundTrip("zip-aes128")
    @Test fun `removes AES-192`() = assertRoundTrip("zip-aes192")
    @Test fun `removes legacy ZipCrypto`() = assertRoundTrip("zip-zipcrypto")
    @Test fun `removes encryption from a mixed archive`() = assertRoundTrip("zip-mixed")

    @Test
    fun `rejects the wrong password without producing output`() {
        val corpus = VectorCorpus.load()
        try {
            ZipAdapter().remove(corpus.bytes("zip-aes256"), corpus.wrongPassword)
            fail("expected WrongPassword")
        } catch (expected: FprException.WrongPassword) {
            assertEquals(3, expected.exitCode)
        }
    }

    @Test
    fun `refuses an archive that is not encrypted`() {
        val corpus = VectorCorpus.load()
        try {
            ZipAdapter().remove(corpus.bytes("zip-plain"), corpus.correctPassword)
            fail("expected PolicyRefused")
        } catch (expected: FprException.PolicyRefused) {
            assertNotNull(expected.message)
        }
    }
}

class OoxmlTest {
    private fun assertDecryptsToAPackage(id: String) {
        val corpus = VectorCorpus.load()
        val output = OoxmlAdapter().remove(corpus.bytes(id), corpus.correctPassword)
        val members = ZipArchive.readMembers(output)
        assertNotNull("$id did not decrypt to an OOXML package", members["[Content_Types].xml"])
    }

    @Test fun `removes encryption from docx`() = assertDecryptsToAPackage("ooxml-docx-agile")
    @Test fun `removes encryption from xlsx`() = assertDecryptsToAPackage("ooxml-xlsx-agile")
    @Test fun `removes encryption from pptx`() = assertDecryptsToAPackage("ooxml-pptx-agile")

    @Test
    fun `rejects the wrong password`() {
        val corpus = VectorCorpus.load()
        try {
            OoxmlAdapter().remove(corpus.bytes("ooxml-docx-agile"), corpus.wrongPassword)
            fail("expected WrongPassword")
        } catch (expected: FprException.WrongPassword) {
            assertEquals(3, expected.exitCode)
        }
    }

    @Test
    fun `refuses documentProtection, which is not encryption`() {
        val corpus = VectorCorpus.load()
        val detection = OoxmlAdapter().detect(corpus.bytes("ooxml-docx-restricted"))
        assertEquals(Protection.OWNER_RESTRICTIONS, detection.protection)
        assertEquals(Removability.REFUSED, detection.removability)
    }
}

class PdfTest {
    @Test
    fun `removes encryption across every standard security revision`() {
        val corpus = VectorCorpus.load()
        for (id in listOf(
            "pdf-rc4-40-user", "pdf-rc4-128-user", "pdf-aes-128-user",
            "pdf-aes-256-r5-user", "pdf-aes-256-r6-user",
        )) {
            val expectedPages = corpus.vector(id).expect.pages!!
            val output = PdfAdapter().remove(corpus.bytes(id), corpus.correctPassword)

            assertEquals("$id still encrypted", Protection.NONE, PdfAdapter().detect(output).protection)
            assertEquals("$id lost pages", expectedPages, PdfAdapter().pageCount(output))
        }
    }

    @Test
    fun `detects owner restrictions and refuses to strip them`() {
        val corpus = VectorCorpus.load()
        val detection = PdfAdapter().detect(corpus.bytes("pdf-owner-restrictions"))
        assertEquals(Protection.OWNER_RESTRICTIONS, detection.protection)
        assertEquals(Removability.REFUSED, detection.removability)

        try {
            PdfAdapter().remove(corpus.bytes("pdf-owner-restrictions"), "")
            fail("expected PolicyRefused")
        } catch (expected: FprException.PolicyRefused) {
            assertNotNull(expected.message)
        }
    }

    @Test
    fun `rejects the wrong password`() {
        val corpus = VectorCorpus.load()
        try {
            PdfAdapter().remove(corpus.bytes("pdf-aes-256-r6-user"), corpus.wrongPassword)
            fail("expected WrongPassword")
        } catch (expected: FprException.WrongPassword) {
            assertEquals(3, expected.exitCode)
        }
    }
}

class SevenZipTest {
    private fun assertRoundTrip(id: String) {
        val corpus = VectorCorpus.load()
        val expected = corpus.members(id)

        val output = SevenZipAdapter().remove(corpus.bytes(id), corpus.correctPassword)

        val recovered = SevenZipAdapter().readMembers(output)
        assertEquals("$id member list", expected.keys, recovered.keys)
        expected.forEach { (name, member) ->
            assertEquals("$id content of $name", member.sha256, sha256Hex(recovered.getValue(name)))
        }
        assertEquals(
            "$id output is still encrypted",
            Protection.NONE, SevenZipAdapter().detect(output).protection,
        )
    }

    @Test fun `removes AES-256 with a plaintext header`() = assertRoundTrip("7z-encrypted-data")
    @Test fun `removes AES-256 with an encrypted header`() = assertRoundTrip("7z-encrypted-header")

    @Test
    fun `detects an encrypted header without the password`() {
        val corpus = VectorCorpus.load()
        val detection = SevenZipAdapter().detect(corpus.bytes("7z-encrypted-header"))
        assertEquals(Protection.USER_PASSWORD, detection.protection)
        assertTrue(detection.algorithm!!.contains("encrypted header"))
    }

    @Test
    fun `rejects the wrong password`() {
        val corpus = VectorCorpus.load()
        try {
            SevenZipAdapter().remove(corpus.bytes("7z-encrypted-data"), corpus.wrongPassword)
            fail("expected WrongPassword")
        } catch (expected: FprException.WrongPassword) {
            assertEquals(3, expected.exitCode)
        }
    }
}

class LegacyOfficeTest {
    @Test
    fun `detects encryption but reports it as unsupported`() {
        val corpus = VectorCorpus.load()
        val detection = LegacyOfficeAdapter().detect(corpus.bytes("legacy-doc-encrypted"))
        assertEquals(FormatId.LEGACY_OFFICE, detection.format)
        assertEquals(Protection.USER_PASSWORD, detection.protection)
        assertEquals(Removability.UNSUPPORTED, detection.removability)
    }

    @Test
    fun `reports an unencrypted legacy document as not protected`() {
        val corpus = VectorCorpus.load()
        assertEquals(
            Protection.NONE,
            LegacyOfficeAdapter().detect(corpus.bytes("legacy-doc-plain")).protection,
        )
    }

    @Test
    fun `remove always refuses rather than pretending`() {
        val corpus = VectorCorpus.load()
        try {
            LegacyOfficeAdapter().remove(corpus.bytes("legacy-doc-encrypted"), corpus.correctPassword)
            fail("expected UnsupportedFormat")
        } catch (expected: FprException.UnsupportedFormat) {
            assertEquals(5, expected.exitCode)
        }
    }
}
