package com.pinmls.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pinmls.app.ui.PinUiState
import com.pinmls.app.ui.PinViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                val vm: PinViewModel = viewModel()
                val state by vm.state.collectAsState()
                Surface(modifier = Modifier.fillMaxSize()) {
                    if (!state.initialized) {
                        OnboardingScreen(state = state, onCreatePin = { vm.createNewPin() })
                    } else {
                        ChatHomeScreen(
                            state = state,
                            onSelectGroup = { vm.selectGroup(it) },
                            onSync = { vm.syncNow() },
                            onSend = { vm.sendMessage(it) },
                            onDismissMnemonic = { vm.dismissMnemonicBanner() },
                            onWipe = { vm.wipeLocalVault() },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun OnboardingScreen(state: PinUiState, onCreatePin: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("PIN-MLS · Android", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text("Chat cifrado E2EE con OpenMLS RFC 9420 + SQLCipher")
        Spacer(Modifier.height(24.dp))
        Button(onClick = onCreatePin, enabled = !state.busy) {
            Text(if (state.busy) "Creando identidad..." else "Crear PIN nuevo")
        }
        Spacer(Modifier.height(16.dp))
        Text(state.status, style = MaterialTheme.typography.bodySmall)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatHomeScreen(
    state: PinUiState,
    onSelectGroup: (String) -> Unit,
    onSync: () -> Unit,
    onSend: (String) -> Unit,
    onDismissMnemonic: () -> Unit,
    onWipe: () -> Unit,
) {
    var draft by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("PIN ${state.pin} · ${if (state.wsOnline) "WSS" else "Offline"}") },
                actions = {
                    TextButton(onClick = onSync) { Text("Sync") }
                    TextButton(onClick = onWipe) { Text("Salir") }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(12.dp),
        ) {
            state.newMnemonicBanner?.let { words ->
                Card(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Guarda tus 12 palabras BIP-39:", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(4.dp))
                        Text(words)
                        TextButton(onClick = onDismissMnemonic) { Text("Ya las guardé") }
                    }
                }
            }

            Text(state.status, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))

            if (state.groups.isEmpty()) {
                Text("Sin chats OpenMLS activos todavía. Pulsa Sync tras recibir un Welcome.")
            } else {
                LazyColumn(modifier = Modifier.heightIn(max = 140.dp)) {
                    items(state.groups) { grp ->
                        ListItem(
                            headlineContent = { Text("PIN ${grp.peerPin}") },
                            supportingContent = { Text("Época ${grp.epoch}") },
                            modifier = Modifier.clickable { onSelectGroup(grp.groupIdB64) },
                        )
                    }
                }
                HorizontalDivider()
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                ) {
                    items(state.activeMessages) { msg ->
                        Text("${if (msg.mine) "Tú" else msg.senderPin}: ${msg.text}")
                        Spacer(Modifier.height(4.dp))
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = draft,
                        onValueChange = { draft = it },
                        modifier = Modifier.weight(1f),
                        placeholder = { Text("Mensaje cifrado OpenMLS...") },
                    )
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = {
                        onSend(draft)
                        draft = ""
                    }) {
                        Text("Enviar")
                    }
                }
            }
        }
    }
}
