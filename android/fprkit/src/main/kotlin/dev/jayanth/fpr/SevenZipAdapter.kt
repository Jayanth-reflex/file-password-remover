package dev.jayanth.fpr

import java.io.ByteArrayOutputStream
import java.io.File
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry
import org.apache.commons.compress.archivers.sevenz.SevenZFile
import org.apache.commons.compress.archivers.sevenz.SevenZMethod
import org.apache.commons.compress.archivers.sevenz.SevenZOutputFile
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel

/**
 * 7-Zip archives with AES-256 encryption.
 *
 * Backed by Apache Commons Compress, which implements both the container and
 * the AES-256/SHA-256 key derivation, including header encryption. It is
 * Apache-2.0, so it does not change this project's licensing story.
 *
 * Path safety: entry names are checked before anything is written, so an
 * archive containing an absolute path or a `..` segment is refused rather than
 * being allowed to escape the output directory.
 */
class SevenZipAdapter {

    fun detect(data: ByteArray): Detection {
        // Opening without a password distinguishes an encrypted header (which
        // hides even the file names) from encrypted content in a plain header.
        val headerEncrypted = try {
            open(data, null).use { file -> file.entries.toList() }
            false
        } catch (error: Exception) {
            if (looksLikePasswordProblem(error)) true else throw corrupt(error)
        }

        if (headerEncrypted) {
            return Detection(
                FormatId.SEVEN_ZIP, Protection.USER_PASSWORD, Removability.REMOVABLE,
                "AES-256 (7-Zip, encrypted header)",
                "Encrypted, including the file list. Supply the password.",
            )
        }

        // With a plaintext header the file list reads fine and only the content
        // is encrypted, so the coder chain is the thing to look at -- and where
        // it is not reported, actually trying to read a member settles it.
        val encrypted = open(data, null).use { file ->
            val byMethod = file.entries.any { entry ->
                entry.contentMethods?.any { it.method == SevenZMethod.AES256SHA256 } == true
            }
            byMethod || !canReadFirstMember(file)
        }
        return if (encrypted) {
            Detection(
                FormatId.SEVEN_ZIP, Protection.USER_PASSWORD, Removability.REMOVABLE,
                "AES-256 (7-Zip)",
                "File names are visible; contents are encrypted. Supply the password.",
            )
        } else {
            Detection(
                FormatId.SEVEN_ZIP, Protection.NONE, Removability.NOT_PROTECTED,
                detail = "Not encrypted.",
            )
        }
    }

    fun remove(data: ByteArray, password: String): ByteArray {
        val entries = LinkedHashMap<String, ByteArray>()
        val directories = LinkedHashSet<String>()

        try {
            open(data, password).use { file ->
                var entry = file.nextEntry
                while (entry != null) {
                    if (isUnsafe(entry.name)) {
                        throw FprException.PolicyRefused(
                            "Refusing '${entry.name}': the archive contains a path that would " +
                                "write outside the output directory."
                        )
                    }
                    if (entry.isDirectory) {
                        directories.add(entry.name)
                    } else {
                        entries[entry.name] = file.readAllBytes()
                    }
                    entry = file.nextEntry
                }
            }
        } catch (error: FprException) {
            throw error
        } catch (error: Exception) {
            // 7-Zip stores no password verifier for content encryption: a wrong
            // password simply decrypts to noise that fails to decompress. So a
            // decode failure while a password is being used is reported as a
            // wrong password, which is overwhelmingly the likely cause.
            throw FprException.WrongPassword()
        }

        // SevenZOutputFile needs a real file to seek in, so the archive is
        // rebuilt in a private temp file that is deleted either way.
        val temporary = File.createTempFile("fpr-7z-", ".7z").apply {
            deleteOnExit()
            setReadable(false, false); setReadable(true, true)
            setWritable(false, false); setWritable(true, true)
        }
        return try {
            SevenZOutputFile(temporary).use { output ->
                output.setContentCompression(SevenZMethod.LZMA2)
                for (name in directories) {
                    val entry = SevenZArchiveEntry().apply {
                        this.name = name
                        isDirectory = true
                    }
                    output.putArchiveEntry(entry)
                    output.closeArchiveEntry()
                }
                for ((name, contents) in entries) {
                    val entry = SevenZArchiveEntry().apply {
                        this.name = name
                        size = contents.size.toLong()
                    }
                    output.putArchiveEntry(entry)
                    output.write(contents)
                    output.closeArchiveEntry()
                }
            }
            temporary.readBytes()
        } finally {
            temporary.delete()
        }
    }

    /** Read every member's plaintext, for verification and for tests. */
    fun readMembers(data: ByteArray, password: String? = null): Map<String, ByteArray> {
        val members = LinkedHashMap<String, ByteArray>()
        open(data, password).use { file ->
            var entry = file.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) members[entry.name] = file.readAllBytes()
                entry = file.nextEntry
            }
        }
        return members
    }

    /** True when a member's bytes come out without a password. */
    private fun canReadFirstMember(file: SevenZFile): Boolean = try {
        var entry = file.nextEntry
        while (entry != null && entry.isDirectory) entry = file.nextEntry
        if (entry == null) true else { file.readAllBytes(); true }
    } catch (error: Exception) {
        false
    }

    private fun open(data: ByteArray, password: String?): SevenZFile =
        SevenZFile.builder()
            .setSeekableByteChannel(SeekableInMemoryByteChannel(data))
            .also { if (password != null) it.setPassword(password) }
            .get()

    private fun isUnsafe(name: String): Boolean {
        val normalised = name.replace('\\', '/')
        return normalised.startsWith("/") ||
            normalised.split('/').any { it == ".." } ||
            normalised.matches(Regex("^[A-Za-z]:.*"))
    }

    private fun looksLikePasswordProblem(error: Exception): Boolean {
        var current: Throwable? = error
        while (current != null) {
            val message = current.message?.lowercase() ?: ""
            if (current is org.apache.commons.compress.PasswordRequiredException ||
                message.contains("password") || message.contains("encrypted")
            ) {
                return true
            }
            current = current.cause
        }
        return false
    }

    private fun corrupt(error: Exception) =
        FprException.CorruptFile("This 7-Zip archive could not be read: ${error.message}")
}

private fun SevenZFile.readAllBytes(): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(1 shl 16)
    while (true) {
        val read = read(buffer)
        if (read < 0) break
        output.write(buffer, 0, read)
    }
    return output.toByteArray()
}
