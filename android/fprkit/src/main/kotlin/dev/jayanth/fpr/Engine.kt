package dev.jayanth.fpr

/**
 * Picks the adapter for a file and runs it.
 *
 * The format is decided from the bytes, never the extension: the test corpus
 * deliberately contains a file named `.zip` that is not one, and trusting the
 * name there would be a security bug rather than a cosmetic one.
 */
class Engine {

    enum class Format { PDF, OOXML, ZIP, SEVEN_ZIP, LEGACY_OFFICE }

    fun detect(data: ByteArray): Detection = when (sniff(data)) {
        Format.PDF -> PdfAdapter().detect(data)
        Format.OOXML -> OoxmlAdapter().detect(data)
        Format.ZIP -> ZipAdapter().detect(data)
        Format.SEVEN_ZIP -> SevenZipAdapter().detect(data)
        Format.LEGACY_OFFICE -> LegacyOfficeAdapter().detect(data)
    }

    fun remove(data: ByteArray, password: String): ByteArray = when (sniff(data)) {
        Format.PDF -> PdfAdapter().remove(data, password)
        Format.OOXML -> OoxmlAdapter().remove(data, password)
        Format.ZIP -> ZipAdapter().remove(data, password)
        Format.SEVEN_ZIP -> SevenZipAdapter().remove(data, password)
        Format.LEGACY_OFFICE -> LegacyOfficeAdapter().remove(data, password)
    }

    /**
     * Write a copy of [data] protected with [password].
     *
     * Only PDF and ZIP can be protected. Every other format refuses rather than
     * quietly handing back a copy with no encryption on it, which would be the
     * most dangerous possible failure for this operation.
     */
    fun protect(data: ByteArray, password: String): ByteArray = when (sniff(data)) {
        Format.PDF -> PdfAdapter().protect(data, password)
        Format.ZIP -> ZipAdapter().protect(data, password)
        Format.OOXML -> throw FprException.UnsupportedFormat(
            "Adding protection to Office documents is not supported yet. This app can " +
                "remove it, but not add it."
        )
        Format.SEVEN_ZIP -> throw FprException.UnsupportedFormat(
            "Adding protection to 7-Zip archives is not supported yet."
        )
        Format.LEGACY_OFFICE -> throw FprException.UnsupportedFormat(
            "Adding protection to Word/Excel 97-2003 files is not supported."
        )
    }

    fun sniff(data: ByteArray): Format {
        if (data.size < 8) throw FprException.CorruptFile("file is too small to identify")

        if (data.startsWith("%PDF-".toByteArray(Charsets.US_ASCII))) return Format.PDF
        if (data.startsWith(byteArrayOf(0x37, 0x7A, 0xBC.toByte(), 0xAF.toByte(), 0x27, 0x1C))) {
            return Format.SEVEN_ZIP
        }

        if (CfbReader.isCfb(data)) {
            // A CFB container is either an encrypted OOXML document or a
            // Word/Excel 97-2003 binary; EncryptionInfo tells them apart.
            return if (CfbReader(data).hasStream("EncryptionInfo")) Format.OOXML
            else Format.LEGACY_OFFICE
        }

        if (data.startsWith("PK".toByteArray(Charsets.US_ASCII))) {
            // OOXML packages are ZIP files too, and declare themselves with a
            // content-type map at a fixed name.
            val members = runCatching { ZipArchive.readMembers(data) }.getOrNull()
            return if (members?.get("[Content_Types].xml") != null) Format.OOXML else Format.ZIP
        }

        throw FprException.UnsupportedFormat("unrecognised file format")
    }
}

private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
