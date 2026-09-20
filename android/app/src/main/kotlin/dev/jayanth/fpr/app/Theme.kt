package dev.jayanth.fpr.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.sp

/**
 * The palette and type scale from docs/design/design-system.md.
 *
 * Deliberately not Material You dynamic colour: the whole point of the design
 * is that brass means "this was verified", and a palette pulled from the user's
 * wallpaper would reassign that meaning at random.
 */
data class FprPalette(
    val ink: Color,
    val surface: Color,
    val line: Color,
    val mist: Color,
    val platinum: Color,
    val brass: Color,
    val patina: Color,
    val oxide: Color,
)

private val DarkPalette = FprPalette(
    ink = Color(0xFF121417),
    surface = Color(0xFF1A1D21),
    line = Color(0xFF2A2E34),
    mist = Color(0xFF8B9198),
    platinum = Color(0xFFECEEF0),
    brass = Color(0xFFC6A664),
    patina = Color(0xFF5E9C86),
    oxide = Color(0xFFA8564B),
)

private val LightPalette = FprPalette(
    ink = Color(0xFFF7F7F5),
    surface = Color(0xFFFFFFFF),
    line = Color(0xFFE4E4E0),
    mist = Color(0xFF6B6F76),
    platinum = Color(0xFF15171A),
    brass = Color(0xFF9A7B3A),
    patina = Color(0xFF3F7A63),
    oxide = Color(0xFF94433A),
)

val LocalPalette = staticCompositionLocalOf { DarkPalette }

@Composable
fun FprTheme(content: @Composable () -> Unit) {
    val palette = if (isSystemInDarkTheme()) DarkPalette else LightPalette
    val scheme = if (isSystemInDarkTheme()) {
        darkColorScheme(
            primary = palette.brass,
            onPrimary = palette.ink,
            background = palette.ink,
            surface = palette.surface,
            onBackground = palette.platinum,
            onSurface = palette.platinum,
            error = palette.oxide,
        )
    } else {
        lightColorScheme(
            primary = palette.brass,
            onPrimary = Color.White,
            background = palette.ink,
            surface = palette.surface,
            onBackground = palette.platinum,
            onSurface = palette.platinum,
            error = palette.oxide,
        )
    }
    CompositionLocalProvider(LocalPalette provides palette) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/** Captions: small, upper case, wide tracked. The hallmark voice. */
@Composable
fun Caption(
    text: String,
    color: Color = LocalPalette.current.mist,
    modifier: androidx.compose.ui.Modifier = androidx.compose.ui.Modifier,
) {
    Text(
        text = text.uppercase(),
        color = color,
        fontSize = 11.sp,
        letterSpacing = 1.4.sp,
        fontWeight = FontWeight.SemiBold,
        textAlign = TextAlign.Start,
        modifier = modifier,
    )
}

/** Marks: monospaced, so columns of evidence line up. */
@Composable
fun Mark(text: String, modifier: androidx.compose.ui.Modifier = androidx.compose.ui.Modifier) {
    Text(
        text = text,
        color = LocalPalette.current.platinum,
        fontFamily = FontFamily.Monospace,
        fontSize = 13.sp,
        modifier = modifier,
    )
}
