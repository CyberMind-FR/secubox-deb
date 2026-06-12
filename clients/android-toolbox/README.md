<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# SecuBox Android ToolBox client (#531)

One-tap **R3 onboarding** for the VILLAGE3B cabine : install the CA,
import the WireGuard profile, verify the tunnel, then open the live
*cartographie sociale*. Replaces the manual Android tutorial.

## Flow
1. **Discover** — scan the kbin QR or type the booth host (`kbin.gk2.secubox.in`).
2. **Install CA** — downloads `/wg/ca.crt`, launches the Android cert-install intent (`KeyChain.createInstallIntent`).
3. **Import profile** — downloads `/wg/profile/new`, hands the `.conf` to the WireGuard app via `FileProvider` + `ACTION_VIEW`.
4. **Verify** — polls `/wg/r3-check` → "Tunnel R3 actif ✓".
5. **Live metrics** — opens `/social/me` (cartographie sociale).

## Build
No Gradle wrapper jar is committed (text-only scaffold). CI builds it:
- **GitHub Actions** `build-android-apk.yml` → debug APK artifact.
Locally (with Android SDK + Gradle 8.9 + JDK 17):
```bash
cd clients/android-toolbox
gradle :app:assembleDebug      # app/build/outputs/apk/debug/app-debug.apk
```

## Constraints (MVP)
- Android 11+ restricts **user CA trust** ; the app launches the install
  intent + guides the manual confirm step. Browsers on the device need
  the CA trusted for the mitm R3 break — this is the known Android
  limitation (documented, not yet automated).
- WireGuard profile import uses the **official WireGuard app** (no embedded
  tunnel in the MVP) — most reliable, no extra native deps.
- Debug APK is self-signed (sideload). Release signing (published
  fingerprint, served from the toolbox) is a follow-up needing a keystore
  secret in CI.

## Tech
Kotlin + Jetpack Compose, minSdk 26 / targetSdk 34. API client is plain
`HttpURLConnection` (no Retrofit/OkHttp) to keep deps + CI minimal.

Package `in.secubox.toolbox`. License `LicenseRef-CMSD-1.0`.
