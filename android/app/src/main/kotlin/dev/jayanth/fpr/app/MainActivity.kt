package dev.jayanth.fpr.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.jayanth.fpr.app.RemovalViewModel.Stage

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme { Surface(Modifier.fillMaxSize()) { RemovalScreen() } }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemovalScreen(model: RemovalViewModel = viewModel()) {
    val context = LocalContext.current
    val stage by model.stage.collectAsState()
    val fileName by model.fileName.collectAsState()
    val password by model.password.collectAsState()

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) model.load(uri, context.displayName(uri))
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Password Remover") }) }) { padding ->
        Column(
            Modifier.padding(padding).padding(16.dp).fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                onClick = { picker.launch(arrayOf("*/*")) },
                modifier = Modifier.fillMaxWidth().testTag("choose-file"),
            ) {
                Text(if (fileName.isEmpty()) "Choose a file" else fileName)
            }
            Text(
                "The file never leaves this device. The app has no network permission.",
                style = MaterialTheme.typography.bodySmall,
            )

            when (val current = stage) {
                is Stage.Empty -> Unit

                is Stage.Inspected -> {
                    DetectionCard(current.detection)
                    if (current.detection.removability.wire == "removable") {
                        OutlinedTextField(
                            value = password,
                            onValueChange = model::setPassword,
                            label = { Text("Password for this file") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            modifier = Modifier.fillMaxWidth().testTag("password-field"),
                        )
                        Button(
                            onClick = { model.removeProtection() },
                            enabled = password.isNotEmpty(),
                            modifier = Modifier.fillMaxWidth().testTag("remove-button"),
                        ) { Text("Remove protection") }
                    }
                }

                is Stage.Working -> Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.testTag("working"),
                ) {
                    CircularProgressIndicator()
                    Text("Working…")
                }

                is Stage.Done -> Card(Modifier.fillMaxWidth().testTag("success")) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Protection removed and verified", style = MaterialTheme.typography.titleMedium)
                        Text(current.detection.detail, style = MaterialTheme.typography.bodySmall)
                        Button(
                            onClick = { context.share(current.output) },
                            modifier = Modifier.testTag("share-button"),
                        ) { Text("Save or share") }
                    }
                }

                is Stage.Failed -> Card(Modifier.fillMaxWidth().testTag("error")) {
                    Column(Modifier.padding(16.dp)) {
                        Text("Could not do that", style = MaterialTheme.typography.titleMedium)
                        Text(current.message, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            if (fileName.isNotEmpty()) {
                TextButton(onClick = { model.reset() }, modifier = Modifier.testTag("start-over")) {
                    Text("Start over")
                }
            }
        }
    }
}

@Composable
private fun DetectionCard(detection: dev.jayanth.fpr.Detection) {
    Card(Modifier.fillMaxWidth().testTag("detection")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("What this file is", style = MaterialTheme.typography.titleMedium)
            Text("Format: ${detection.format.wire.uppercase()}")
            Text("Protection: ${detection.protection.wire}")
            detection.algorithm?.let { Text("Algorithm: $it") }
            Text(detection.detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun android.content.Context.displayName(uri: Uri): String {
    contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (it.moveToFirst()) return it.getString(0)
    }
    return uri.lastPathSegment ?: "file"
}

private fun android.content.Context.share(file: java.io.File) {
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
