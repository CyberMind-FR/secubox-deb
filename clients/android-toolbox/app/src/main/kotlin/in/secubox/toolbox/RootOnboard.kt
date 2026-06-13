// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Root-mode fully-automated silent R3 onboarding (#538).
// All actions are gated behind an explicit "root auto" tap in the UI.
package `in`.secubox.toolbox

import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory

class RootOnboard(private val api: ToolboxApi, private val cacheDir: File) {

    /** A line appended to the on-screen log during the silent run. */
    fun interface Logger { fun log(line: String) }

    data class Outcome(val caInstalled: Boolean, val wgUp: Boolean, val verified: Boolean,
                       val wgViaApp: Boolean)

    // ── system CA install (silent, root) ──

    /**
     * OpenSSL `subject_hash_old` (pre-1.0 hash) computed WITHOUT openssl :
     * MD5 of the DER-encoded subject name, first 4 bytes as a uint32
     * little-endian, formatted "%08x". This is the filename the Android
     * system cacerts store uses (<hash>.0).
     */
    fun subjectHashOld(pem: ByteArray): String {
        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(pem.inputStream()) as java.security.cert.X509Certificate
        val subjectDer = cert.subjectX500Principal.encoded
        val md5 = MessageDigest.getInstance("MD5").digest(subjectDer)
        val h = (md5[0].toLong() and 0xff) or
                ((md5[1].toLong() and 0xff) shl 8) or
                ((md5[2].toLong() and 0xff) shl 16) or
                ((md5[3].toLong() and 0xff) shl 24)
        return String.format("%08x", h)
    }

    /**
     * Install the CA into the SYSTEM trust store so EVERY app (not just
     * those opting into user CAs) trusts it. Uses the bind-mount-over-
     * cacerts technique that works on Android 10–14 (incl. the conscrypt
     * APEX). Non-persistent across reboot — fine for a temporary cabine
     * diagnostic; the app can also unmount to revert.
     */
    fun installCaSystem(log: Logger): Boolean {
        log.log("• Téléchargement du CA…")
        val pem = api.download("/wg/ca.pem", "village3b-ca.pem", cacheDir).readBytes()
        val hash = subjectHashOld(pem)
        log.log("• CA hash : $hash.0")
        val local = File(cacheDir, "$hash.0").apply { writeBytes(pem) }

        // Push the cert to a root-readable scratch path, then bind-mount a
        // populated copy of the system store over the live cacerts dir.
        val pushed = "/data/local/tmp/sbx-$hash.0"
        val push = RootShell.install(local, pushed, "644")
        if (!push.ok) { log.log("✗ push échoué : ${push.err.trim()}"); return false }

        val r = RootShell.runScript(
            "set -e",
            "CERT_DIR=/system/etc/security/cacerts",
            "TMP=/data/local/tmp/sbx-cacerts",
            "rm -rf \$TMP; mkdir -p \$TMP",
            // seed with the existing system + APEX certs so nothing is lost
            "cp -f \$CERT_DIR/* \$TMP/ 2>/dev/null || true",
            "cp -f /apex/com.android.conscrypt/cacerts/* \$TMP/ 2>/dev/null || true",
            "cp -f $pushed \$TMP/$hash.0",
            "chmod 644 \$TMP/* 2>/dev/null || true",
            "chown 0:0 \$TMP/* 2>/dev/null || true",
            "chcon u:object_r:system_security_cacerts_file:s0 \$TMP/* 2>/dev/null || true",
            // bind-mount over the live store (and the APEX path on 14)
            "mount -o bind \$TMP \$CERT_DIR",
            "[ -d /apex/com.android.conscrypt/cacerts ] && mount -o bind \$TMP /apex/com.android.conscrypt/cacerts 2>/dev/null || true",
            "echo OK",
        )
        if (r.ok && r.out.contains("OK")) {
            log.log("✓ CA installé dans le magasin système (toutes les apps le font confiance)")
            return true
        }
        log.log("✗ install CA système : ${r.err.trim().ifBlank { r.out.trim() }}")
        return false
    }

    fun removeCaSystem(log: Logger): Boolean {
        val r = RootShell.runScript(
            "umount /system/etc/security/cacerts 2>/dev/null || true",
            "umount /apex/com.android.conscrypt/cacerts 2>/dev/null || true",
            "echo OK",
        )
        log.log(if (r.ok) "✓ CA système retiré (démonté)" else "✗ démontage : ${r.err.trim()}")
        return r.ok
    }

    // ── WireGuard bring-up ──

    /** Parse the wg-quick .conf into the fields we need. */
    private data class WgConf(val privKey: String, val address: String,
                              val pubKey: String, val endpoint: String, val allowed: String)

    private fun parse(conf: String): WgConf? {
        var pk = ""; var addr = ""; var pub = ""; var ep = ""; var aip = ""
        conf.lineSequence().forEach { raw ->
            val l = raw.trim()
            when {
                l.startsWith("PrivateKey", true) -> pk = l.substringAfter("=").trim()
                l.startsWith("Address", true)    -> addr = l.substringAfter("=").trim()
                l.startsWith("PublicKey", true)  -> pub = l.substringAfter("=").trim()
                l.startsWith("Endpoint", true)   -> ep = l.substringAfter("=").trim()
                l.startsWith("AllowedIPs", true) -> aip = l.substringAfter("=").trim()
            }
        }
        return if (pk.isNotBlank() && pub.isNotBlank() && ep.isNotBlank()) WgConf(pk, addr, pub, ep, aip) else null
    }

    /**
     * Bring the tunnel up natively with root IF the kernel has WireGuard
     * + `wg`/`ip`. Returns true on success ; false means the caller
     * should fall back to the WireGuard-app handoff.
     */
    fun setupWireguardRoot(log: Logger): Boolean {
        if (!RootShell.hasKernelWireguard()) {
            log.log("• Noyau sans module WireGuard — bascule sur l'app WireGuard")
            return false
        }
        log.log("• Génération du profil WireGuard…")
        val conf = api.downloadProfile(cacheDir).readText()
        val wg = parse(conf) ?: run { log.log("✗ profil illisible"); return false }
        val iface = "wg-village3b"
        val r = RootShell.runScript(
            "set -e",
            "ip link del $iface 2>/dev/null || true",
            "ip link add $iface type wireguard",
            "echo '${wg.privKey}' > /data/local/tmp/sbx-wg.key && chmod 600 /data/local/tmp/sbx-wg.key",
            "wg set $iface private-key /data/local/tmp/sbx-wg.key peer ${wg.pubKey} endpoint ${wg.endpoint} allowed-ips ${wg.allowed.ifBlank { "0.0.0.0/0" }} persistent-keepalive 25",
            "rm -f /data/local/tmp/sbx-wg.key",
            if (wg.address.isNotBlank()) "ip addr add ${wg.address} dev $iface 2>/dev/null || true" else ":",
            "ip link set $iface up",
            "for n in ${wg.allowed.replace(",", " ")}; do ip route replace \$n dev $iface 2>/dev/null || true; done",
            "echo OK",
        )
        if (r.ok && r.out.contains("OK")) { log.log("✓ Tunnel $iface actif (root, natif)"); return true }
        log.log("✗ WG natif : ${r.err.trim().ifBlank { r.out.trim() }} — bascule sur l'app")
        return false
    }

    /** Run the whole silent sequence. Blocking — call off-main. */
    fun runSilent(log: Logger): Outcome {
        val ca = installCaSystem(log)
        val wgRoot = setupWireguardRoot(log)
        var verified = false
        if (wgRoot) {
            log.log("• Vérification R3…")
            Thread.sleep(1500)
            val (t, ip) = api.r3Check()
            verified = t
            log.log(if (t) "✓ Tunnel R3 confirmé (${ip ?: "?"})" else "• Pas encore confirmé — réessaie la vérification")
        }
        return Outcome(caInstalled = ca, wgUp = wgRoot, verified = verified, wgViaApp = !wgRoot)
    }
}
