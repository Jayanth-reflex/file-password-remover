package dev.jayanth.fpr

import java.io.ByteArrayOutputStream
import java.util.Base64
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

/**
 * Office Open XML documents using ECMA-376 *agile* encryption
 * ([MS-OFFCRYPTO] 2.3.4.10): an AES-encrypted package inside a CFB container,
 * keyed by an iterated SHA-512 over the password.
 */
class OoxmlAdapter {

    // [MS-OFFCRYPTO] 2.3.4.12 -- block keys that diversify the derived key.
    private val verifierInputBlockKey =
        byteArrayOf(0xFE.toByte(), 0xA7.toByte(), 0xD2.toByte(), 0x76, 0x3B, 0x4B, 0x9E.toByte(), 0x79)
    private val verifierValueBlockKey =
        byteArrayOf(0xD7.toByte(), 0xAA.toByte(), 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E)
    private val keyValueBlockKey =
        byteArrayOf(0x14, 0x6E, 0x0B, 0xE7.toByte(), 0xAB.toByte(), 0xAC.toByte(), 0xD0.toByte(), 0xD6.toByte())

    private data class Descriptor(
        val keyDataSalt: ByteArray,
        val keyDataBlockSize: Int,
        val spinCount: Int,
        val passwordSalt: ByteArray,
        val keyBits: Int,
        val hashAlgorithm: String,
        val encryptedVerifierHashInput: ByteArray,
        val encryptedVerifierHashValue: ByteArray,
        val encryptedKeyValue: ByteArray,
    )

    fun detect(data: ByteArray): Detection {
        if (CfbReader.isCfb(data)) {
            val container = CfbReader(data)
            if (!container.hasStream("EncryptionInfo")) {
                return Detection(
                    FormatId.OOXML, Protection.UNKNOWN, Removability.UNSUPPORTED,
                    detail = "Compound file without an EncryptionInfo stream.",
                )
            }
            val descriptor = readDescriptor(container)
            return Detection(
                FormatId.OOXML, Protection.USER_PASSWORD, Removability.REMOVABLE,
                "AES-${descriptor.keyBits} (ECMA-376 agile, ${descriptor.hashAlgorithm}, " +
                    "${descriptor.spinCount} spins)",
                "Encrypted. Supply the password the document was protected with.",
            )
        }

        val members = ZipArchive.readMembers(data)
        if (members["[Content_Types].xml"] == null) {
            return Detection(
                FormatId.UNKNOWN, Protection.UNKNOWN, Removability.UNSUPPORTED,
                detail = "Not an Office Open XML package.",
            )
        }
        for ((name, contents) in members) {
            if (!name.endsWith("settings.xml")) continue
            if (String(contents, Charsets.UTF_8).contains("documentProtection")) {
                return Detection(
                    FormatId.OOXML, Protection.OWNER_RESTRICTIONS, Removability.REFUSED,
                    detail = "Marked read-only with documentProtection. The content is not " +
                        "encrypted, so removing that flag is a bypass rather than decryption -- " +
                        "this tool does not do it.",
                )
            }
        }
        return Detection(
            FormatId.OOXML, Protection.NONE, Removability.NOT_PROTECTED,
            detail = "Not encrypted. ${members.size} part(s).",
        )
    }

    fun remove(data: ByteArray, password: String): ByteArray {
        if (!CfbReader.isCfb(data)) {
            val detection = detect(data)
            throw FprException.PolicyRefused(
                if (detection.protection == Protection.OWNER_RESTRICTIONS) detection.detail
                else "This document is not encrypted; there is nothing to remove."
            )
        }
        val container = CfbReader(data)
        val descriptor = readDescriptor(container)
        val base = iteratedHash(password, descriptor.passwordSalt, descriptor.spinCount)
        val keyLength = descriptor.keyBits / 8

        // Verify before anything else: a wrong password stops here.
        val verifierInput = Crypto.aesCbcDecrypt(
            descriptor.encryptedVerifierHashInput,
            derive(base, verifierInputBlockKey, keyLength), descriptor.passwordSalt,
        )
        val expectedHash = Crypto.aesCbcDecrypt(
            descriptor.encryptedVerifierHashValue,
            derive(base, verifierValueBlockKey, keyLength), descriptor.passwordSalt,
        )
        val actualHash = Crypto.sha512(verifierInput.copyOfRange(0, 16))
        if (!Crypto.constantTimeEquals(actualHash, expectedHash.copyOfRange(0, 64))) {
            throw FprException.WrongPassword()
        }

        val secretKey = Crypto.aesCbcDecrypt(
            descriptor.encryptedKeyValue, derive(base, keyValueBlockKey, keyLength),
            descriptor.passwordSalt,
        ).copyOfRange(0, keyLength)

        return decryptPackage(
            container.stream("EncryptedPackage"), secretKey, descriptor.keyDataSalt,
            descriptor.keyDataBlockSize,
        )
    }

    private fun decryptPackage(
        packageStream: ByteArray, secretKey: ByteArray, keyDataSalt: ByteArray, blockSize: Int,
    ): ByteArray {
        if (packageStream.size < 8) {
            throw FprException.CorruptFile("EncryptedPackage stream is too short")
        }
        val reader = ByteReader(packageStream)
        val declaredLength = reader.u64().toInt()
        val output = ByteArrayOutputStream(maxOf(declaredLength, 0))

        var segment = 0
        while (reader.remaining > 0) {
            val take = minOf(SEGMENT_LENGTH, reader.remaining)
            // Each segment gets its own IV, derived from the salt and its index.
            val salted = keyDataSalt + byteArrayOf(
                (segment and 0xFF).toByte(), ((segment shr 8) and 0xFF).toByte(),
                ((segment shr 16) and 0xFF).toByte(), ((segment shr 24) and 0xFF).toByte(),
            )
            val iv = Crypto.sha512(salted).copyOfRange(0, blockSize)
            val whole = take - (take % 16)
            val chunk = reader.bytes(whole)
            if (take % 16 != 0) reader.bytes(take % 16)
            output.write(Crypto.aesCbcDecrypt(chunk, secretKey, iv))
            segment += 1
        }

        val decrypted = output.toByteArray()
        if (declaredLength > decrypted.size) {
            throw FprException.CorruptFile(
                "declared package length $declaredLength exceeds ${decrypted.size} decrypted bytes"
            )
        }
        return decrypted.copyOf(declaredLength)
    }

    /** H0 = SHA512(salt || UTF16LE(password)); Hn = SHA512(LE32(n) || Hn-1). */
    private fun iteratedHash(password: String, salt: ByteArray, spinCount: Int): ByteArray {
        var hash = Crypto.sha512(salt + password.toByteArray(Charsets.UTF_16LE))
        for (index in 0 until spinCount) {
            val block = byteArrayOf(
                (index and 0xFF).toByte(), ((index shr 8) and 0xFF).toByte(),
                ((index shr 16) and 0xFF).toByte(), ((index shr 24) and 0xFF).toByte(),
            )
            hash = Crypto.sha512(block + hash)
        }
        return hash
    }

    private fun derive(hash: ByteArray, blockKey: ByteArray, length: Int): ByteArray =
        Crypto.sha512(hash + blockKey).copyOfRange(0, length)

    private fun readDescriptor(container: CfbReader): Descriptor {
        val stream = container.stream("EncryptionInfo")
        if (stream.size <= 8) throw FprException.CorruptFile("EncryptionInfo stream is too short")
        val header = ByteReader(stream)
        val major = header.u16()
        val minor = header.u16()
        if (major != 4 || minor != 4) {
            throw FprException.UnsupportedFormat(
                "This document uses ECMA-376 $major.$minor encryption. Only agile " +
                    "encryption (4.4) is supported."
            )
        }

        val xml = stream.copyOfRange(8, stream.size)
        // This XML comes from the file being inspected, so external entities
        // must never be resolved. Android's parser does not implement all of
        // these feature names -- it rejects them outright rather than ignoring
        // them -- so each is set independently and the EntityResolver below is
        // the backstop that works on every runtime.
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        for (feature in listOf(
            "http://apache.org/xml/features/disallow-doctype-decl",
            "http://xml.org/sax/features/external-general-entities",
            "http://xml.org/sax/features/external-parameter-entities",
            "http://apache.org/xml/features/nonvalidating/load-external-dtd",
        )) {
            runCatching {
                factory.setFeature(feature, feature.endsWith("disallow-doctype-decl"))
            }
        }
        runCatching { factory.isXIncludeAware = false }
        factory.isExpandEntityReferences = false

        val builder = factory.newDocumentBuilder()
        builder.setEntityResolver { _, _ ->
            org.xml.sax.InputSource(java.io.ByteArrayInputStream(ByteArray(0)))
        }
        val document = builder.parse(xml.inputStream())

        fun element(local: String): Element = document.getElementsByTagName("*").let { nodes ->
            (0 until nodes.length).asSequence()
                .mapNotNull { nodes.item(it) as? Element }
                .firstOrNull { it.tagName.substringAfterLast(':') == local }
                ?: throw FprException.CorruptFile("<$local> missing from EncryptionInfo")
        }

        val keyData = element("keyData")
        val encryptedKey = element("encryptedKey")
        fun Element.base64(name: String): ByteArray =
            Base64.getDecoder().decode(getAttribute(name).ifEmpty { "" })

        return Descriptor(
            keyDataSalt = keyData.base64("saltValue"),
            keyDataBlockSize = keyData.getAttribute("blockSize").toIntOrNull() ?: 16,
            spinCount = encryptedKey.getAttribute("spinCount").toIntOrNull() ?: 100_000,
            passwordSalt = encryptedKey.base64("saltValue"),
            keyBits = encryptedKey.getAttribute("keyBits").toIntOrNull() ?: 256,
            hashAlgorithm = encryptedKey.getAttribute("hashAlgorithm").ifEmpty { "SHA512" },
            encryptedVerifierHashInput = encryptedKey.base64("encryptedVerifierHashInput"),
            encryptedVerifierHashValue = encryptedKey.base64("encryptedVerifierHashValue"),
            encryptedKeyValue = encryptedKey.base64("encryptedKeyValue"),
        )
    }

    private companion object {
        const val SEGMENT_LENGTH = 4096
    }
}
