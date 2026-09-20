package dev.jayanth.fpr.app

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONObject

/**
 * The same vector corpus the JVM tests use, read from the device.
 *
 * CI pushes build/vectors to the device before running these tests; the path is
 * passed through as an instrumentation argument.
 */
class DeviceCorpus(private val root: File, private val manifest: JSONObject) {

    data class Member(val name: String, val size: Int, val sha256: String)

    private fun vector(id: String): JSONObject {
        val vectors = manifest.getJSONArray("vectors")
        for (index in 0 until vectors.length()) {
            val vector = vectors.getJSONObject(index)
            if (vector.getString("id") == id) return vector
        }
        error("vector '$id' is not in the corpus")
    }

    val correctPassword: String get() = manifest.getJSONObject("passwords").getString("correct")
    val wrongPassword: String get() = manifest.getJSONObject("passwords").getString("wrong")

    fun bytes(id: String): ByteArray = File(root, vector(id).getString("file")).readBytes()

    fun members(id: String): Map<String, Member> {
        val expect = vector(id).optJSONObject("expect") ?: return emptyMap()
        val members = expect.optJSONArray("members") ?: return emptyMap()
        return (0 until members.length()).associate { index ->
            val member = members.getJSONObject(index)
            member.getString("name") to Member(
                member.getString("name"), member.getInt("size"), member.getString("sha256"),
            )
        }
    }

    companion object {
        fun load(): DeviceCorpus {
            val arguments = InstrumentationRegistry.getArguments()
            val root = File(arguments.getString("fprVectors") ?: "/data/local/tmp/fpr-vectors")
            val manifest = File(root, "manifest.json")
            require(manifest.isFile) { "vector corpus missing at $root" }
            return DeviceCorpus(root, JSONObject(manifest.readText()))
        }
    }
}
