package dev.jayanth.fpr

/**
 * Word/Excel 97-2003 binary documents.
 *
 * Detection only. These use RC4 or RC4+CryptoAPI inside a CFB container, which
 * this port does not implement -- so it says so, instead of reporting a success
 * it cannot deliver.
 */
class LegacyOfficeAdapter {

    fun detect(data: ByteArray): Detection {
        if (!CfbReader.isCfb(data)) {
            throw FprException.CorruptFile("not a Word/Excel 97-2003 document")
        }
        val container = CfbReader(data)

        if (container.hasStream("WordDocument")) {
            val stream = container.stream("WordDocument")
            if (stream.size < 12) {
                throw FprException.CorruptFile("File Information Block is truncated")
            }
            val reader = ByteReader(stream)
            val identifier = reader.u16()
            if (identifier != WORD_IDENTIFIER) {
                throw FprException.CorruptFile(
                    "unexpected wIdent 0x${identifier.toString(16)} in WordDocument stream"
                )
            }
            reader.seek(0x0A)
            val flags = reader.u16()
            if (flags and ENCRYPTED_FLAG == 0) {
                return Detection(
                    FormatId.LEGACY_OFFICE, Protection.NONE, Removability.NOT_PROTECTED,
                    detail = "Word 97-2003 document, not encrypted.",
                )
            }
            return Detection(
                FormatId.LEGACY_OFFICE, Protection.USER_PASSWORD, Removability.UNSUPPORTED,
                "RC4 or RC4+CryptoAPI ([MS-DOC])",
                "Encrypted Word 97-2003 document. This app cannot decrypt the legacy RC4 " +
                    "schemes; use the desktop command-line tool for this file.",
            )
        }

        if (container.hasStream("Workbook") || container.hasStream("Book")) {
            return Detection(
                FormatId.LEGACY_OFFICE, Protection.UNKNOWN, Removability.UNSUPPORTED,
                detail = "Excel 97-2003 workbook. Encryption state is recorded in BIFF records " +
                    "this app does not parse; use the desktop command-line tool.",
            )
        }

        throw FprException.UnsupportedFormat("compound file with no recognised Office streams")
    }

    fun remove(data: ByteArray, password: String): ByteArray {
        val detail = runCatching { detect(data).detail }.getOrNull()
        throw FprException.UnsupportedFormat(
            detail ?: "Legacy Office decryption is not available in this app; use the desktop CLI."
        )
    }

    private companion object {
        const val WORD_IDENTIFIER = 0xA5EC
        const val ENCRYPTED_FLAG = 0x0100
    }
}
