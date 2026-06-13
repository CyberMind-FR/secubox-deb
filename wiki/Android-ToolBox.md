<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# 📱 Android ToolBox — one-tap R3 onboarding

The **SecuBox Android ToolBox** is a tiny companion app that onboards a
phone onto the VILLAGE3B *cabine* in one tap: it installs the cabine CA,
brings up the WireGuard R3 tunnel, verifies reachability, then opens the
live *cartographie sociale*. It replaces the manual Android tutorial.

- Source : [`clients/android-toolbox/`](https://github.com/CyberMind-FR/secubox-deb/tree/master/clients/android-toolbox)
- Package : `in.secubox.toolbox` · Kotlin + Jetpack Compose · minSdk 26 / targetSdk 34
- License : `LicenseRef-CMSD-1.0`

## Install

Grab the APK directly from the cabine — the toolbox serves it:

```
https://kbin.<board>.secubox.in/wg/toolbox.apk
```

The onboard panels in the kbin WebUI expose a **📱 Installer l'app ToolBoX
(1-tap)** button pointing at that endpoint. When the cabine has a locally
fetched build it serves it (`application/vnd.android.package-archive`);
otherwise it 302-redirects to the latest GitHub release asset
`secubox-toolbox-android.apk`.

> The MVP APK is **debug-signed** (sideload — enable *Install unknown
> apps*). A release-signed build with a published fingerprint is a
> follow-up (needs a keystore secret in CI).

## Onboarding flows

### Manual path (non-rooted)
1. **Discover** — scan the kbin QR or type the booth host (`kbin.<board>.secubox.in`).
2. **Install CA** — downloads `/wg/ca.crt`, launches the Android cert-install
   intent (`KeyChain.createInstallIntent`).
3. **Import profile** — downloads `/wg/profile/new`, hands the `.conf` to the
   official WireGuard app (`FileProvider` + `ACTION_VIEW`).
4. **Verify** — polls `/wg/r3-check` → *Tunnel R3 actif ✓*.
5. **Live metrics** — opens `/social/me` (cartographie sociale).

Android 11+ restricts **user CA trust**, so on a non-rooted device the
browser CA confirm is a guided manual step.

### Root path — fully-automated, silent (#538)
When the device is **rooted**, the Discover step shows an extra
**⚡ Installation automatique (root)** button. One tap runs everything with
no further interaction (a `RootAuto` step streams the progress log):

1. **System CA install** — downloads `/wg/ca.pem`, computes the OpenSSL
   `subject_hash_old` in pure Kotlin, then bind-mounts a populated copy of
   the trust store over `/system/etc/security/cacerts` (+ the conscrypt
   APEX on Android 14), restoring the SELinux context
   `u:object_r:system_security_cacerts_file:s0`. **Every** app trusts the
   cabine CA — not just user-CA opt-in apps. Reversible via `umount`.
2. **Native WireGuard** — if the kernel has the WireGuard module + `wg`/`ip`,
   the tunnel comes up natively (`ip link add … type wireguard` + `wg set`) —
   no WireGuard app required.
3. **Auto R3 verify** — polls `/wg/r3-check`.

If the kernel lacks WireGuard, the root path installs the system CA then
falls back to the manual WireGuard-app handoff.

**Safety** — every root action is gated behind the explicit tap; nothing
runs as root unless the operator chooses root mode on their own device.
Code: `RootShell.kt` (su wrapper) + `RootOnboard.kt` (silent sequence).

## Build (CI)

No Gradle wrapper jar is committed (text-only scaffold). CI builds it:

- GitHub Actions `build-android-apk.yml` → debug APK artifact on push to
  `master` / PRs touching `clients/android-toolbox/**`.
- Tagging `android-v*` publishes the APK as a release asset.

Locally (Android SDK + Gradle 8.9 + JDK 17):

```bash
cd clients/android-toolbox
gradle :app:assembleDebug   # app/build/outputs/apk/debug/app-debug.apk
```

## Cabine endpoints consumed

| Endpoint | Purpose |
|----------|---------|
| `/wg/ca.crt` / `/wg/ca.pem` | cabine CA (user / system store) |
| `/wg/profile/new` | fresh WireGuard `.conf` |
| `/wg/r3-check` | tunnel reachability probe |
| `/social/me` | live cartographie sociale |
| `/wg/toolbox.apk` | the APK itself |
