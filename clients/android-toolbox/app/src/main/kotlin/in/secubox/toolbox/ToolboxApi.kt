// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package `in`.secubox.toolbox

import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Minimal HTTP client for the SecuBox ToolBox R3 endpoints. Uses
 * HttpURLConnection (no Retrofit/OkHttp) to keep the dependency graph
 * and CI minimal. All calls are blocking — invoke off the main thread.
 *
 * Endpoints (served on the kbin vhost, e.g. kbin.gk2.secubox.in) :
 *   GET /wg/ca.crt        -> CA root cert (Android DER/PEM)
 *   GET /wg/profile/new   -> wg-quick .conf (one fresh peer per call)
 *   GET /wg/r3-check       -> {"tunnel": bool, "peer_ip": "10.99.1.x"}
 *   GET /social/me         -> per-client cartographie sociale (web view)
 */
class ToolboxApi(rawHost: String) {

    // Accept "kbin.gk2.secubox.in", "https://kbin…", trailing slashes…
    val base: String = rawHost.trim()
        .removePrefix("https://").removePrefix("http://")
        .trim('/')
        .let { "https://$it" }

    val socialMeUrl: String get() = "$base/social/me"

    private fun open(path: String): HttpURLConnection =
        (URL("$base$path").openConnection() as HttpURLConnection).apply {
            connectTimeout = 8000
            readTimeout = 12000
            setRequestProperty("User-Agent", "secubox-toolbox-android/0.1")
            instanceFollowRedirects = true
        }

    /** Download a file (CA or WG profile) into the app cache, return it. */
    fun download(path: String, outName: String, cacheDir: File): File {
        val c = open(path)
        try {
            if (c.responseCode !in 200..299)
                throw RuntimeException("HTTP ${c.responseCode} for $path")
            val out = File(cacheDir, outName)
            c.inputStream.use { input -> out.outputStream().use { input.copyTo(it) } }
            return out
        } finally { c.disconnect() }
    }

    fun downloadCa(cacheDir: File): File = download("/wg/ca.crt", "village3b-ca.crt", cacheDir)
    fun downloadProfile(cacheDir: File): File = download("/wg/profile/new", "village3b-toolbox.conf", cacheDir)

    /** R3 tunnel status. Returns (onTunnel, peerIp?). */
    fun r3Check(): Pair<Boolean, String?> {
        val c = open("/wg/r3-check")
        try {
            if (c.responseCode !in 200..299) return false to null
            val body = c.inputStream.bufferedReader().readText()
            val j = JSONObject(body)
            return j.optBoolean("tunnel", false) to j.optString("peer_ip", null)
        } catch (_: Exception) {
            return false to null
        } finally { c.disconnect() }
    }

    /** Cheap reachability probe for the discover step. */
    fun reachable(): Boolean = try {
        val c = open("/wg/r3-check"); val ok = c.responseCode in 200..499; c.disconnect(); ok
    } catch (_: Exception) { false }
}
