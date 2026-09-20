package dev.jayanth.fpr.app

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.jayanth.fpr.Detection
import dev.jayanth.fpr.Engine
import dev.jayanth.fpr.FprException
import dev.jayanth.fpr.Protection
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
        data class Failed(val message: String) : Stage
    }

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

    val needsPassword: Boolean
        get() = (_stage.value as? Stage.Inspected)?.detection?.removability?.wire == "removable"

    fun load(uri: Uri, displayName: String) {
        _stage.value = Stage.Empty
        _password.value = ""
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
                    Stage.Done(write(output, _fileName.value), verified)
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
        _stage.value = Stage.Empty
    }

    /** Write into app-private storage, never over the original. */
    private fun write(data: ByteArray, name: String): File {
        val base = name.substringBeforeLast('.', name)
        val extension = name.substringAfterLast('.', "")
        val directory = File(getApplication<Application>().cacheDir, "output").apply { mkdirs() }
        val target = File(
            directory,
            if (extension.isEmpty()) "$base-unprotected" else "$base-unprotected.$extension",
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
