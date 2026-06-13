// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: Android ToolBox client (#531)
// One-tap R3 onboarding : discover -> install CA -> import WG profile ->
// verify tunnel -> live cartographie sociale. Replaces the manual
// multi-step Android tutorial.
package `in`.secubox.toolbox

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.security.KeyChain
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Cosmos = Color(0xFF0A0A0F)
private val Gold = Color(0xFFC9A84C)
private val Cyan = Color(0xFF00D4FF)
private val Matrix = Color(0xFF00FF41)
private val Cinnabar = Color(0xFFE63946)
private val TextPrimary = Color(0xFFE8E6D9)

enum class Step { Discover, RootAuto, InstallCa, ImportProfile, Verify, Done }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { OnboardApp() }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardApp() {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    var host by remember { mutableStateOf("kbin.gk2.secubox.in") }
    var step by remember { mutableStateOf(Step.Discover) }
    var status by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var onTunnel by remember { mutableStateOf(false) }
    var peerIp by remember { mutableStateOf<String?>(null) }
    val api = remember(host) { ToolboxApi(host) }
    var rootAvail by remember { mutableStateOf(false) }
    val rootLog = remember { mutableStateListOf<String>() }
    val prefs = remember {
        ctx.getSharedPreferences("secubox-toolbox", android.content.Context.MODE_PRIVATE)
    }
    var autoTried by remember { mutableStateOf(false) }

    // The whole root-mode silent run, reused by the ⚡ button AND the
    // zero-tap auto-launch (#551/#558). NO onboarded gate — it auto-runs
    // every launch (idempotent: re-asserts CA + WG). Reachability is
    // RETRIED so a WiFi/tunnel race at launch doesn't kill the auto-run.
    val runRootAuto: () -> Unit = {
        busy = true; status = ""; rootLog.clear()
        scope.launch {
            // poll reachability up to ~9 s (network may still be settling)
            var ok = false
            for (attempt in 1..6) {
                ok = withContext(Dispatchers.IO) { api.reachable() }
                if (ok) break
                status = "Recherche de la borne… ($attempt)"
                kotlinx.coroutines.delay(1500)
            }
            if (!ok) {
                busy = false; status = "Borne injoignable — vérifie le réseau."
            } else {
                step = Step.RootAuto
                val onb = RootOnboard(api, ctx.cacheDir)
                val out = withContext(Dispatchers.IO) {
                    onb.runSilent { line -> scope.launch(Dispatchers.Main) { rootLog.add(line) } }
                }
                busy = false
                onTunnel = out.verified
                when {
                    out.verified -> step = Step.Done
                    out.wgViaApp -> { step = Step.ImportProfile
                        status = "CA installé en root ✓ — termine le tunnel via l'app WireGuard." }
                    else -> { step = Step.Verify
                        status = "Active le tunnel puis vérifie." }
                }
            }
        }
    }

    // Detect root once, off the main thread.
    LaunchedEffect(Unit) { rootAvail = withContext(Dispatchers.IO) { RootShell.available() } }
    // Zero-tap (#558): on a rooted device, auto-run the silent onboarding
    // on every launch — no gate. (Boot-time auto-run is handled by
    // BootReceiver + OnboardService so it runs without opening the app.)
    LaunchedEffect(rootAvail) {
        if (rootAvail && !autoTried && step == Step.Discover) {
            autoTried = true
            runRootAuto()
        }
    }

    MaterialTheme(colorScheme = darkColorScheme(
        primary = Gold, secondary = Cyan, background = Cosmos, surface = Cosmos,
        onBackground = TextPrimary, onSurface = TextPrimary,
    )) {
        Surface(Modifier.fillMaxSize(), color = Cosmos) {
            Column(
                Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text("📡 VILLAGE3B", color = Gold, fontSize = 26.sp, fontWeight = FontWeight.Bold)
                Text("ToolBoX — installation R3", color = TextPrimary, fontSize = 14.sp)
                Spacer(Modifier.height(20.dp))

                Stepper(step)
                Spacer(Modifier.height(20.dp))

                when (step) {
                    Step.Discover -> {
                        OutlinedTextField(
                            value = host, onValueChange = { host = it },
                            label = { Text("Borne (kbin…)") }, singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("Scanne le QR de la cabine ou saisis l'adresse, puis Suivant.",
                            color = TextPrimary, fontSize = 12.sp)
                        Spacer(Modifier.height(16.dp))
                        BigButton("Suivant", busy) {
                            busy = true; status = "Vérification de la borne…"
                            scope.launch {
                                val ok = withContext(Dispatchers.IO) { api.reachable() }
                                busy = false
                                if (ok) { step = Step.InstallCa; status = "" }
                                else status = "Borne injoignable — vérifie l'adresse / le réseau."
                            }
                        }
                        if (rootAvail) {
                            Spacer(Modifier.height(10.dp))
                            Text("🔓 Root détecté — l'installation se lance automatiquement. " +
                                 "Tu peux aussi la relancer ici.",
                                color = Matrix, fontSize = 12.sp)
                            Spacer(Modifier.height(6.dp))
                            OutlinedButton(onClick = runRootAuto, modifier = Modifier.fillMaxWidth(),
                               border = BorderStroke(1.dp, Matrix),
                               colors = ButtonDefaults.outlinedButtonColors(contentColor = Matrix)) {
                                Text("⚡ Installation automatique (root)", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                    Step.RootAuto -> {
                        StepBody("Installation automatique (root)",
                            "CA système + tunnel WireGuard, sans intervention.")
                        Surface(color = Color(0xFF0E0E15), shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(12.dp)) {
                                rootLog.forEach { line ->
                                    Text(line, color = if (line.startsWith("✗")) Cinnabar
                                        else if (line.startsWith("✓")) Matrix else TextPrimary,
                                        fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                                }
                                if (busy) {
                                    Spacer(Modifier.height(6.dp))
                                    CircularProgressIndicator(Modifier.size(18.dp), color = Gold, strokeWidth = 2.dp)
                                }
                            }
                        }
                    }
                    Step.InstallCa -> {
                        StepBody("1 · Installer le certificat (CA R3)",
                            "Le certificat permet l'analyse TLS de la cabine. " +
                            "Android te demandera de confirmer (Paramètres → Sécurité → " +
                            "Certificat utilisateur).")
                        BigButton("Installer le certificat", busy) {
                            busy = true
                            scope.launch {
                                try {
                                    val ca = withContext(Dispatchers.IO) { api.downloadCa(ctx.cacheDir) }
                                    val der = ca.readBytes()
                                    val intent = KeyChain.createInstallIntent().apply {
                                        putExtra(KeyChain.EXTRA_CERTIFICATE, der)
                                        putExtra(KeyChain.EXTRA_NAME, "VILLAGE3B ToolBoX CA")
                                    }
                                    ctx.startActivity(intent)
                                    status = "Confirme l'installation dans Android, puis Suivant."
                                } catch (e: Exception) {
                                    status = "Échec téléchargement CA : ${e.message}"
                                } finally { busy = false }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        TextButton(onClick = {
                            ctx.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                        }) { Text("Ouvrir Paramètres sécurité", color = Cyan) }
                        Spacer(Modifier.height(8.dp))
                        BigButton("Suivant", false) { step = Step.ImportProfile; status = "" }
                    }
                    Step.ImportProfile -> {
                        StepBody("2 · Importer le profil WireGuard",
                            "On génère un profil dédié et on l'ouvre dans l'app WireGuard. " +
                            "Active le tunnel dans WireGuard, puis reviens ici.")
                        BigButton("Importer dans WireGuard", busy) {
                            busy = true
                            scope.launch {
                                try {
                                    val conf = withContext(Dispatchers.IO) { api.downloadProfile(ctx.cacheDir) }
                                    val uri = FileProvider.getUriForFile(
                                        ctx, "${ctx.packageName}.fileprovider", conf)
                                    val intent = Intent(Intent.ACTION_VIEW).apply {
                                        setDataAndType(uri, "application/octet-stream")
                                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                        setPackage("com.wireguard.android")
                                    }
                                    try { ctx.startActivity(intent) }
                                    catch (_: Exception) {
                                        // WireGuard not installed -> open Play / generic chooser.
                                        ctx.startActivity(Intent(Intent.ACTION_VIEW,
                                            Uri.parse("https://play.google.com/store/apps/details?id=com.wireguard.android")))
                                        status = "Installe l'app WireGuard puis réessaie."
                                    }
                                } catch (e: Exception) {
                                    status = "Échec profil : ${e.message}"
                                } finally { busy = false }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        BigButton("Suivant", false) { step = Step.Verify; status = "" }
                    }
                    Step.Verify -> {
                        StepBody("3 · Vérifier le tunnel R3",
                            "Active le tunnel dans WireGuard, puis vérifie.")
                        BigButton("Vérifier", busy) {
                            busy = true; status = "Vérification…"
                            scope.launch {
                                val (t, ip) = withContext(Dispatchers.IO) { api.r3Check() }
                                busy = false; onTunnel = t; peerIp = ip
                                if (t) { step = Step.Done; status = "" }
                                else status = "Pas encore sur le tunnel — active WireGuard puis réessaie."
                            }
                        }
                    }
                    Step.Done -> {
                        Icon(Icons.Filled.CheckCircle, null, tint = Matrix, modifier = Modifier.size(56.dp))
                        Text("Tunnel R3 actif ✓", color = Matrix, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        peerIp?.let { Text("pair : $it", color = TextPrimary, fontSize = 12.sp) }
                        Spacer(Modifier.height(20.dp))
                        BigButton("🕸️ Voir ma cartographie sociale", false) {
                            ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(api.socialMeUrl)))
                        }
                    }
                }

                if (status.isNotBlank()) {
                    Spacer(Modifier.height(16.dp))
                    Text(status, color = if (status.contains("Échec") || status.contains("injoignable")) Cinnabar else Cyan,
                        fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun Stepper(cur: Step) {
    val steps = listOf(Step.Discover, Step.InstallCa, Step.ImportProfile, Step.Verify, Step.Done)
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        steps.forEach { s ->
            val done = s.ordinal < cur.ordinal
            val active = s == cur
            Box(Modifier.size(if (active) 14.dp else 10.dp)) {
                Surface(shape = MaterialTheme.shapes.small,
                    color = when { done -> Matrix; active -> Gold; else -> Color(0xFF333333) },
                    modifier = Modifier.fillMaxSize()) {}
            }
        }
    }
}

@Composable
private fun StepBody(title: String, body: String) {
    Text(title, color = Gold, fontSize = 16.sp, fontWeight = FontWeight.Bold)
    Spacer(Modifier.height(8.dp))
    Text(body, color = TextPrimary, fontSize = 13.sp)
    Spacer(Modifier.height(16.dp))
}

@Composable
private fun BigButton(label: String, busy: Boolean, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = !busy, modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(containerColor = Gold, contentColor = Cosmos)) {
        if (busy) CircularProgressIndicator(Modifier.size(18.dp), color = Cosmos, strokeWidth = 2.dp)
        else Text(label, fontWeight = FontWeight.Bold)
    }
}
