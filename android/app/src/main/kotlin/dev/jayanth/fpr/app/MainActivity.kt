package dev.jayanth.fpr.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.jayanth.fpr.Detection
import dev.jayanth.fpr.FprKit
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            FprTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = LocalPalette.current.ink,
                ) { DocumentScreen() }
            }
        }
    }
}

@Composable
fun DocumentScreen(model: RemovalViewModel = viewModel()) {
    val context = LocalContext.current
    val palette = LocalPalette.current
    val stage by model.stage.collectAsState()
    val fileName by model.fileName.collectAsState()
    val password by model.password.collectAsState()
    val verification by model.verification.collectAsState()
    var generatePassword by remember { mutableStateOf(true) }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? -> if (uri != null) model.load(uri, context.displayName(uri)) }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        // ---- masthead
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Caption("Local only", color = palette.brass)
            Text(
                "File Password Remover",
                color = palette.platinum,
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold,
                lineHeight = 34.sp,
            )
            Text(
                "Lock a file, or open one you have the password for. " +
                    "Nothing leaves this device.",
                color = palette.mist,
                fontSize = 14.sp,
            )
        }

        // ---- source
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionMark("Source")
            Surface(
                color = palette.surface,
                shape = RoundedCornerShape(10.dp),
                onClick = { picker.launch(arrayOf("*/*")) },
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("choose-file"),
            ) {
                Row(
                    Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        if (fileName.isEmpty()) "Choose a file" else fileName,
                        color = palette.platinum,
                        maxLines = 1,
                    )
                }
            }
            if (fileName.isNotEmpty()) {
                TextButton(
                    onClick = { model.reset() },
                    modifier = Modifier.testTag("start-over"),
                ) { Text("Start over", color = palette.oxide) }
            }
        }

        when (val current = stage) {
            is RemovalViewModel.Stage.Empty -> Unit

            is RemovalViewModel.Stage.Inspected -> {
                DetectionCard(current.detection)
                when (model.available) {
                    RemovalViewModel.Action.REMOVE -> RemoveControls(model, password)
                    RemovalViewModel.Action.PROTECT -> ProtectControls(
                        model = model,
                        password = password,
                        generatePassword = generatePassword,
                        onGenerateChanged = { generatePassword = it },
                    )
                    RemovalViewModel.Action.NOTHING -> Unit
                }
            }

            is RemovalViewModel.Stage.Working -> Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.testTag("working"),
            ) {
                CircularProgressIndicator(color = palette.brass, strokeWidth = 2.dp)
                Text("Working…", color = palette.mist)
            }

            is RemovalViewModel.Stage.Done -> Outcome(
                title = "Protection removed",
                detail = current.detection.detail,
                output = current.output,
                verification = verification,
            )

            is RemovalViewModel.Stage.Protected -> {
                Outcome(
                    title = "Protected and verified",
                    detail = current.detection.detail,
                    output = current.output,
                    verification = verification,
                )
                current.generated?.let { GeneratedPassword(it) }
            }

            is RemovalViewModel.Stage.Failed -> Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.testTag("error"),
            ) {
                SectionMark("Could not do that")
                Text(current.message, color = palette.oxide, fontSize = 13.sp)
            }
        }

        // The version is here so a bug report can name the build it came from.
        // It reads from FprKit rather than BuildConfig, so what is shown is the
        // version of the engine that produced the result above it.
        Caption("Version ${FprKit.VERSION}. No network permission, no telemetry. Apache-2.0.")
    }
}

@Composable
private fun DetectionCard(detection: Detection) {
    val palette = LocalPalette.current
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionMark("What this file is")
        Surface(
            color = palette.surface,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth().testTag("detection"),
        ) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Field("Format", detection.format.wire.uppercase())
                Field("Protection", detection.protection.wire)
                detection.algorithm?.let { Field("Algorithm", it) }
                Text(detection.detail, color = palette.mist, fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Caption(label)
        Spacer(Modifier.weight(1f).widthIn(min = 16.dp))
        Mark(value)
    }
}

@Composable
private fun RemoveControls(model: RemovalViewModel, password: String) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionMark("Password")
        PasswordField(
            value = password,
            onValueChange = model::setPassword,
            label = "Password for this file",
            tag = "password-field",
        )
        PrimaryButton(
            "Remove protection",
            enabled = password.isNotEmpty(),
            tag = "remove-button",
        ) { model.removeProtection() }
    }
}

@Composable
private fun ProtectControls(
    model: RemovalViewModel,
    password: String,
    generatePassword: Boolean,
    onGenerateChanged: (Boolean) -> Unit,
) {
    val palette = LocalPalette.current
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionMark("Add a password")
        SingleChoiceSegmentedButtonRow(
            Modifier.fillMaxWidth().testTag("password-source")
        ) {
            SegmentedButton(
                selected = generatePassword,
                onClick = { onGenerateChanged(true) },
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
            ) { Text("Generate one") }
            SegmentedButton(
                selected = !generatePassword,
                onClick = { onGenerateChanged(false) },
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
            ) { Text("Use my own") }
        }

        if (generatePassword) {
            Text(
                "A strong password will be made for you and shown once. " +
                    "This app cannot recover it later.",
                color = palette.mist,
                fontSize = 13.sp,
            )
        } else {
            PasswordField(
                value = password,
                onValueChange = model::setPassword,
                label = "Password to set",
                tag = "new-password-field",
            )
        }

        PrimaryButton(
            "Protect this file",
            enabled = generatePassword || password.isNotEmpty(),
            tag = "protect-button",
        ) { model.protectFile(generatePassword) }
    }
}

@Composable
private fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    tag: String,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth().testTag(tag),
    )
}

@Composable
private fun Outcome(
    title: String,
    detail: String,
    output: File,
    verification: Map<String, String>,
) {
    val context = LocalContext.current
    val palette = LocalPalette.current
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        SectionMark("Done")
        Text(
            title,
            color = palette.patina,
            fontSize = 18.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.testTag("success"),
        )
        Text(detail, color = palette.mist, fontSize = 13.sp)
        HallmarkRow(verification)
        TextButton(
            onClick = { context.share(output) },
            modifier = Modifier.heightIn(min = 48.dp).testTag("share-button"),
        ) { Text("Save or share", color = palette.brass) }
    }
}

/**
 * Shown once, and never stored. Losing it means losing the file, so it is the
 * loudest thing on screen when it appears.
 */
@Composable
private fun GeneratedPassword(password: String) {
    val context = LocalContext.current
    val palette = LocalPalette.current
    Surface(
        color = palette.surface,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, palette.brass, RoundedCornerShape(12.dp)),
    ) {
        Column(
            Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            SectionMark("Password")
            Text(
                password,
                color = palette.platinum,
                fontFamily = FontFamily.Monospace,
                fontSize = 20.sp,
                modifier = Modifier.testTag("generated-password"),
            )
            TextButton(
                onClick = { context.copy(password) },
                modifier = Modifier.heightIn(min = 48.dp).testTag("copy-password"),
            ) { Text("Copy password", color = palette.brass) }
            Text(
                "Save this now. It is shown once, and this app cannot recover it.",
                color = palette.brass,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}

@Composable
private fun PrimaryButton(
    label: String,
    enabled: Boolean,
    tag: String,
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(tag),
    ) { Text(label, fontWeight = FontWeight.SemiBold) }
}

private fun Context.displayName(uri: Uri): String {
    contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (it.moveToFirst()) return it.getString(0)
    }
    return uri.lastPathSegment ?: "file"
}

private fun Context.copy(password: String) {
    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    // Marked sensitive so it stays out of clipboard previews and history.
    val clip = ClipData.newPlainText("password", password).apply {
        description.extras = android.os.PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
    }
    clipboard.setPrimaryClip(clip)
}

private fun Context.share(file: File) {
    val uri = FileProvider.getUriForFile(this, "$packageName.files", file)
    startActivity(
        Intent.createChooser(
            Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            },
            "Save or share",
        )
    )
}
