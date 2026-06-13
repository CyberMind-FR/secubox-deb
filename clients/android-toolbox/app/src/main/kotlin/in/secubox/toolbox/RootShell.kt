// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package `in`.secubox.toolbox

import java.io.File

/**
 * Thin wrapper around `su` for the root-mode silent onboarding (#538).
 * Every action is gated behind an explicit user tap in the UI — nothing
 * runs as root without the operator choosing root mode on their own
 * device.
 */
object RootShell {

    data class Result(val code: Int, val out: String, val err: String) {
        val ok get() = code == 0
    }

    /** True if a `su` binary is on PATH and grants a root shell. */
    fun available(): Boolean = try {
        run("id -u").out.trim() == "0"
    } catch (_: Exception) { false }

    /** Run a single command in a root shell. Blocking — call off-main. */
    fun run(cmd: String): Result {
        val p = ProcessBuilder("su", "-c", cmd)
            .redirectErrorStream(false)
            .start()
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        val code = p.waitFor()
        return Result(code, out, err)
    }

    /** Run several commands in ONE root shell (atomic-ish, keeps remount). */
    fun runScript(vararg lines: String): Result {
        val p = ProcessBuilder("su").redirectErrorStream(false).start()
        p.outputStream.bufferedWriter().use { w ->
            lines.forEach { w.write(it); w.write("\n") }
            w.write("exit $?\n")
        }
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        val code = p.waitFor()
        return Result(code, out, err)
    }

    /** Push a local file to a root-owned path via cat (avoids cp quirks). */
    fun install(src: File, destPath: String, mode: String = "644"): Result {
        val b64 = android.util.Base64.encodeToString(src.readBytes(), android.util.Base64.NO_WRAP)
        return runScript(
            "echo '$b64' | base64 -d > '$destPath'",
            "chmod $mode '$destPath'",
        )
    }

    /** Kernel has WireGuard + the `wg` tool available to root? */
    fun hasKernelWireguard(): Boolean = try {
        val w = run("command -v wg || ls /system/*bin/wg 2>/dev/null")
        val ip = run("command -v ip")
        w.out.isNotBlank() && ip.out.isNotBlank()
    } catch (_: Exception) { false }
}
