package dev.jayanth.fpr.app

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.jayanth.fpr.Detection
import dev.jayanth.fpr.Engine
import dev.jayanth.fpr.FprException
import dev.jayanth.fpr.FormatId
import dev.jayanth.fpr.PasswordGenerator
import dev.jayanth.fpr.Protection
import dev.jayanth.fpr.Removability
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Drives one file through detect -> remove -> verify -> write.
 *
 * The password is held only for the duration of the call and cleared straight
 * afterwards. It is never logged, never put in a URI, and never persisted.
 */
class RemovalViewModel(application: Application) : AndroidViewModel(application) {

    sealed interface Stage {
        data object Empty : Stage
        data class Inspected(val detection: Detection) : Stage
        data object Working : Stage
        data class Done(val output: File, val detection: Detection) : Stage

        /** [generated] is set only when this app made the password. */
        data class Protected(
            val output: File,
            val detection: Detection,
            val generated: String?,
        ) : Stage

        data class Failed(val message: String) : Stage
    }

    /** What can be done with the file that is loaded. */
    enum class Action { REMOVE, PROTECT, NOTHING }

    private val _stage = MutableStateFlow<Stage>(Stage.Empty)
    val stage: StateFlow<Stage> = _stage.asStateFlow()

    private val _fileName = MutableStateFlow("")
    val fileName: StateFlow<String> = _fileName.asStateFlow()

    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    private var source: ByteArray? = null

    fun setPassword(value: String) {
        _password.value = value
    }

    private val _verification = MutableStateFlow<Map<String, String>>(emptyMap())

    /** Evidence from re-reading the file that was just written. */
    val verification: StateFlow<Map<String, String>> = _verification.asStateFlow()

    val needsPassword: Boolean
        get() = available == Action.REMOVE

    /**
     * Removing and protecting are the same gesture in opposite directions, so
     * the file itself decides which one is on offer.
     */
    val available: Action
        get() {
            val detection = (_stage.value as? Stage.Inspected)?.detection ?: return Action.NOTHING
            if (detection.removability == Removability.REMOVABLE) return Action.REMOVE
            if (detection.protection == Protection.NONE && canProtect(detection.format)) {
                return Action.PROTECT
            }
            return Action.NOTHING
        }

    private fun canProtect(format: FormatId) =
        format == FormatId.PDF || format == FormatId.ZIP

    /**
     * Protect the loaded file with the typed password, or a generated one.
     *
     * The file is written before the password is handed back, so a failure
     * between the two cannot leave a locked file whose password was never
     * shown. A password the user chose is not returned: it is already theirs.
     */
    fun protectFile(generatePassword: Boolean) {
        val data = source ?: return
        _stage.value = Stage.Working
        val chosen = if (generatePassword) PasswordGenerator.generate() else _password.value
        _password.value = ""

        viewModelScope.launch {
            _stage.value = try {
                withContext(Dispatchers.Default) {
                    val output = Engine().protect(data, chosen)

                    val verified = Engine().detect(output)
                    if (verified.protection != Protection.USER_PASSWORD) {
                        throw FprException.InternalError("The output file is not protected.")
                    }
                    _verification.value = runCatching {
                        Engine().evidence(output, chosen)
                    }.getOrDefault(emptyMap())

                    Stage.Protected(
                        write(output, _fileName.value, "-protected"),
                        verified,
                        if (generatePassword) chosen else null,
                    )
                }
            } catch (error: Exception) {
                Stage.Failed(describe(error))
            }
        }
    }

    fun load(uri: Uri, displayName: String) {
        _stage.value = Stage.Empty
        _password.value = ""
        // Evidence belongs to one run; it must never sit under a different file.
        _verification.value = emptyMap()
        viewModelScope.launch {
            try {
                val data = withContext(Dispatchers.IO) {
                    getApplication<Application>().contentResolver.openInputStream(uri)
                        ?.use { it.readBytes() }
                        ?: throw FprException.CorruptFile("That file could not be opened.")
                }
                source = data
                _fileName.value = displayName
                _stage.value = Stage.Inspected(withContext(Dispatchers.Default) { Engine().detect(data) })
            } catch (error: Exception) {
                source = null
                _stage.value = Stage.Failed(describe(error))
            }
        }
    }

    fun removeProtection() {
        val data = source ?: return
        _stage.value = Stage.Working
        val secret = _password.value
        // Drop our copy as soon as the work is queued.
        _password.value = ""

        viewModelScope.launch {
            _stage.value = try {
                withContext(Dispatchers.Default) {
                    val output = Engine().remove(data, secret)

                    // Verify by re-reading what we are about to hand back,
                    // rather than trusting that the work succeeded.
                    val verified = Engine().detect(output)
                    if (verified.protection != Protection.NONE) {
                        throw FprException.InternalError("The output file is still protected.")
                    }
                    _verification.value = runCatching {
                        Engine().evidence(output)
                    }.getOrDefault(emptyMap())
                    Stage.Done(write(output, _fileName.value, "-unprotected"), verified)
                }
            } catch (error: Exception) {
                Stage.Failed(describe(error))
            }
        }
    }

    fun reset() {
        source = null
        _fileName.value = ""
        _password.value = ""
        _verification.value = emptyMap()
        _stage.value = Stage.Empty
    }

    /** Write into app-private storage, never over the original. */
    private fun write(data: ByteArray, name: String, suffix: String): File {
        val base = name.substringBeforeLast('.', name)
        val extension = name.substringAfterLast('.', "")
        val directory = File(getApplication<Application>().cacheDir, "output").apply { mkdirs() }
        val target = File(
            directory,
            if (extension.isEmpty()) "$base$suffix" else "$base$suffix.$extension",
        )
        // Write to a sibling first and rename, so a partial file is never
        // visible under the final name.
        val staging = File(directory, target.name + ".part")
        staging.writeBytes(data)
        if (!staging.renameTo(target)) {
            staging.delete()
            throw FprException.InternalError("The output file could not be written.")
        }
        return target
    }

    companion object {
        fun describe(error: Throwable): String = when (error) {
            is FprException.WrongPassword ->
                "That password did not open the file. Check it and try again."
            is FprException -> error.message ?: "That did not work."
            else -> error.message ?: "That did not work."
        }
    }
}
