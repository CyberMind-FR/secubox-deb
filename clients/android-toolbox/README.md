<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# SecuBox Android ToolBox client (#531)

One-tap **R3 onboarding** for the VILLAGE3B cabine : install the CA,
import the WireGuard profile, verify the tunnel, then open the live
*cartographie sociale*. Replaces the manual Android tutorial.

## Flow (manual path)
1. **Discover** — scan the kbin QR or type the booth host (`kbin.gk2.secubox.in`).
2. **Install CA** — downloads `/wg/ca.crt`, launches the Android cert-install intent (`KeyChain.createInstallIntent`).
3. **Import profile** — downloads `/wg/profile/new`, hands the `.conf` to the WireGuard app via `FileProvider` + `ACTION_VIEW`.
4. **Verify** — polls `/wg/r3-check` → "Tunnel R3 actif ✓".
5. **Live metrics** — opens `/social/me` (cartographie sociale).

## Root path — real zero-tap, fully automated (#538, #551, #558)
On a **rooted** device the app onboards with **zero taps**, two ways:

- **On launch** — auto-detects root and runs the silent sequence immediately
  every launch (no gate), retrying reachability while WiFi/tunnel settle.
- **On boot** — a `BOOT_COMPLETED` receiver starts a short foreground service
  (`OnboardService`) that runs the same silent sequence **without opening the
  app**, then stops. After one reboot the device self-onboards.

The **⚡ Installation automatique (root)** button remains as a manual
re-trigger. Two interactions are **mandated by Android and unavoidable** for
any app: the sideload install confirm ("install unknown apps") and the
first-time superuser (Magisk/su) grant prompt. Everything after those is
zero-tap. Steps:

1. **System CA install** — downloads `/wg/ca.pem`, computes the OpenSSL
   `subject_hash_old` in pure Kotlin, and bind-mounts a populated copy of
   the trust store over `/system/etc/security/cacerts` (+ the conscrypt
   APEX path on Android 14), restoring the SELinux context
   (`u:object_r:system_security_cacerts_file:s0`). **Every** app trusts the
   cabine CA — not just user-CA opt-in apps. Reversible via `umount`.
2. **Native WireGuard** — if the kernel has the WireGuard module + `wg`/`ip`,
   brings the tunnel up natively (`ip link add … type wireguard` + `wg set`),
   no WireGuard app required.
3. **Auto R3 verify** — polls `/wg/r3-check`.

**Fallback** — if the kernel lacks WireGuard, the root path installs the
system CA then hands off to the manual WireGuard-app flow (steps 3–5 above).

All root actions are **gated behind the explicit tap** — nothing runs as
root without the operator choosing root mode on their own device.
See `RootShell.kt` (su wrapper) and `RootOnboard.kt` (silent sequence).

## Build
No Gradle wrapper jar is committed (text-only scaffold). CI builds it:
- **GitHub Actions** `build-android-apk.yml` → debug APK artifact.
Locally (with Android SDK + Gradle 8.9 + JDK 17):
```bash
cd clients/android-toolbox
gradle :app:assembleDebug      # app/build/outputs/apk/debug/app-debug.apk
```

## Constraints (MVP)
- Android 11+ restricts **user CA trust** ; the *manual* path launches the
  install intent + guides the confirm step. Browsers on the device need the
  CA trusted for the mitm R3 break — this is the known Android limitation on
  non-rooted devices. **Rooted devices bypass it entirely** via the system
  CA install (see Root path above).
- The *manual* path imports the WireGuard profile via the **official
  WireGuard app** (no embedded tunnel) — most reliable, no extra native
  deps. The *root* path brings the tunnel up natively with the kernel module.
- Debug APK is self-signed (sideload). Release signing (published
  fingerprint, served from the toolbox) is a follow-up needing a keystore
  secret in CI.

## Tech
Kotlin + Jetpack Compose, minSdk 26 / targetSdk 34. API client is plain
`HttpURLConnection` (no Retrofit/OkHttp) to keep deps + CI minimal.

Package `in.secubox.toolbox`. License `LicenseRef-CMSD-1.0`.
