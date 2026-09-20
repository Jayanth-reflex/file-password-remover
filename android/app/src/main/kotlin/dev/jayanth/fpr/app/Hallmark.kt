package dev.jayanth.fpr.app

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/**
 * The verification evidence, as a row of struck marks.
 *
 * The signature element of the interface. It appears only after a verified
 * success, and every mark in it is data the engine read back out of the file it
 * just wrote.
 */
@Composable
fun HallmarkRow(verification: Map<String, String>, modifier: Modifier = Modifier) {
    if (verification.isEmpty()) return
    val palette = LocalPalette.current

    // Shorter captions, matching the CLI renderer, so the interfaces name the
    // same evidence the same way. Only the caption is shortened.
    val captions = mapOf(
        "content_digest" to "digest",
        "content_scope" to "scope",
        "docinfo_keys" to "docinfo",
        "has_xmp" to "xmp",
            )
    val marks = verification.toSortedMap().map { (key, value) ->
        (captions[key] ?: key) to value
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .semantics {
                contentDescription =
                    "Verified. " + marks.joinToString(", ") { "${it.first} ${it.second}" }
            },
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        HorizontalDivider(color = palette.line, thickness = 1.dp)
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            marks.forEach { (caption, value) ->
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Caption(caption, color = palette.brass)
                    Mark(value)
                }
            }
        }
    }
}

/** A caption over a hairline: the section marker. */
@Composable
fun SectionMark(label: String, modifier: Modifier = Modifier) {
    val palette = LocalPalette.current
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Caption(label)
        HorizontalDivider(
            color = palette.line,
            thickness = 1.dp,
            modifier = Modifier.weight(1f).height(1.dp).padding(top = 1.dp),
        )
    }
}
