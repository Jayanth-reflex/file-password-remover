package dev.jayanth.fpr

/** ZIP archives: WinZip AES (AE-1/AE-2) and legacy PKWARE ZipCrypto. */
class ZipAdapter {

    fun detect(data: ByteArray): Detection {
        val entries = ZipArchive.readCentralDirectory(data)
        val encrypted = entries.filter { it.isEncrypted }

        if (encrypted.isEmpty()) {
            return Detection(
                FormatId.ZIP, Protection.NONE, Removability.NOT_PROTECTED,
                detail = "Not encrypted. ${entries.size} entr${if (entries.size == 1) "y" else "ies"}.",
            )
        }

        encrypted.firstOrNull { it.usesStrongEncryption && it.aes == null }?.let {
            return Detection(
                FormatId.ZIP, Protection.UNKNOWN, Removability.UNSUPPORTED,
                detail = "'${it.name}' uses PKWare Strong Encryption (SES), which is " +
                    "certificate-based and not supported.",
            )
        }

        val aesFields = encrypted.mapNotNull { it.aes }
        val algorithm = when {
            aesFields.size == encrypted.size && aesFields.isNotEmpty() ->
                "AES-${aesFields.first().keyBits} (WinZip AE-${aesFields.first().vendorVersion})"
            aesFields.isEmpty() -> "ZipCrypto (legacy PKWARE)"
            else -> "mixed: AES and ZipCrypto"
        }

        val plural = if (encrypted.size == 1) "entry is" else "entries are"
        return Detection(
            FormatId.ZIP, Protection.USER_PASSWORD, Removability.REMOVABLE, algorithm,
            "${encrypted.size} of ${entries.size} $plural encrypted. Supply the password.",
        )
    }

    /**
     * Decrypt every encrypted entry and return an archive with no encryption.
     *
     * The password is required and never guessed: a wrong one fails here and
     * produces nothing.
     */
    fun remove(data: ByteArray, password: String): ByteArray {
        val entries = ZipArchive.readCentralDirectory(data)
        if (entries.none { it.isEncrypted }) {
            throw FprException.PolicyRefused("This ZIP is not encrypted; there is nothing to remove.")
        }
        val passwordBytes = password.toByteArray(Charsets.UTF_8)

        val decrypted = entries.map { entry ->
            val payload = ZipArchive.payload(data, entry)
            val compressed = when {
                !entry.isEncrypted -> payload
                entry.aes != null -> decryptAes(payload, entry.aes!!, passwordBytes, entry.name)
                else -> decryptZipCrypto(payload, passwordBytes, entry)
            }
            val method = entry.effectiveMethod
            val plaintext = ZipArchive.decompress(compressed, method, entry.uncompressedSize.toInt())
            DecryptedEntry(
                entry, compressed, plaintext.size,
                // AE-2 zeroes the stored CRC, so it is recomputed from the
                // recovered plaintext rather than trusted.
                ZipArchive.crc32(plaintext), method,
            )
        }
        return ZipArchive.write(decrypted)
    }

    private fun decryptAes(
        payload: ByteArray, aes: AesExtraField, password: ByteArray, name: String,
    ): ByteArray {
        val keyLength = aes.keyBits / 8
        if (payload.size < aes.saltLength + 2 + 10) {
            throw FprException.CorruptFile("AES payload of $name is too short")
        }
        val reader = ByteReader(payload)
        val salt = reader.bytes(aes.saltLength)
        val verifier = reader.bytes(2)
        val ciphertext = reader.bytes(payload.size - aes.saltLength - 2 - 10)
        val authCode = reader.bytes(10)

        val derived = Crypto.pbkdf2Sha1(password, salt, 1000, keyLength * 2 + 2)
        val encryptionKey = derived.copyOfRange(0, keyLength)
        val authenticationKey = derived.copyOfRange(keyLength, keyLength * 2)
        val expectedVerifier = derived.copyOfRange(keyLength * 2, keyLength * 2 + 2)

        if (!Crypto.constantTimeEquals(expectedVerifier, verifier)) throw FprException.WrongPassword()
        // The 2-byte verifier accepts 1 wrong password in 65536, so the MAC is
        // what actually decides and is always checked.
        val mac = Crypto.hmacSha1(ciphertext, authenticationKey).copyOfRange(0, 10)
        if (!Crypto.constantTimeEquals(mac, authCode)) throw FprException.WrongPassword()

        return Crypto.winZipAesCrypt(ciphertext, encryptionKey)
    }

    private fun decryptZipCrypto(
        payload: ByteArray, password: ByteArray, entry: ZipEntry,
    ): ByteArray {
        if (payload.size < 12) {
            throw FprException.CorruptFile("ZipCrypto payload of ${entry.name} is too short")
        }
        val stream = ZipCryptoStream(password)
        val header = stream.decrypt(payload.copyOfRange(0, 12))
        // Bit 3 means the CRC was unknown at write time, so the check byte is the
        // high byte of the DOS time instead. ([APPNOTE] 6.1.6.)
        val expected = if (entry.flags and 0x8 != 0) {
            (entry.modTime shr 8) and 0xFF
        } else {
            ((entry.crc shr 24) and 0xFF).toInt()
        }
        if ((header[11].toInt() and 0xFF) != expected) throw FprException.WrongPassword()
        return stream.decrypt(payload.copyOfRange(12, payload.size))
    }
}
