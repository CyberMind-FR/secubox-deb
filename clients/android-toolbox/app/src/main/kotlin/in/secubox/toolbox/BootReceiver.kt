// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// #558 — boot-completed → kick the onboarding foreground service so a
// rooted, operator-owned cabine device self-onboards with zero taps after
// a reboot (no need to open the app).
package `in`.secubox.toolbox

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val a = intent?.action ?: return
        if (a == Intent.ACTION_BOOT_COMPLETED || a == Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            ContextCompat.startForegroundService(
                context, Intent(context, OnboardService::class.java),
            )
        }
    }
}
