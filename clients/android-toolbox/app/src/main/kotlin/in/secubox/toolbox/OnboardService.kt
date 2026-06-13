// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// #558 — full-auto onboarding service. Started on boot (BootReceiver). On a
// rooted device it runs the silent R3 onboarding (system CA + native WG +
// verify) with zero taps, retrying reachability while the network settles,
// then stops itself. Non-root / unreachable → it just stops (the launcher
// activity remains the manual path).
package `in`.secubox.toolbox

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class OnboardService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val CHAN = "sbx-onboard"
    private val NID = 4201

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NID, buildNotification())
        scope.launch {
            try { runOnce() } finally { stopSelf() }
        }
        return START_NOT_STICKY
    }

    private suspend fun runOnce() {
        // root is the precondition for the silent path; bail quietly otherwise.
        if (!RootShell.available()) return
        val host = getSharedPreferences("secubox-toolbox", Context.MODE_PRIVATE)
            .getString("host", null) ?: "kbin.gk2.secubox.in"
        val api = ToolboxApi(host)
        // network may still be coming up after boot — retry ~30 s.
        var ok = false
        for (i in 1..15) {
            ok = api.reachable()
            if (ok) break
            kotlinx.coroutines.delay(2000)
        }
        if (!ok) return
        RootOnboard(api, cacheDir).runSilent { /* headless: no UI log */ }
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(
                NotificationChannel(CHAN, "SecuBox onboarding",
                    NotificationManager.IMPORTANCE_LOW),
            )
        }
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHAN) else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setContentTitle("VILLAGE3B")
            .setContentText("Activation R3 automatique…")
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
