# Companion — QR pairing/auth + optional WireGuard LAN tunnel — Design (draft)

**Date:** 2026-07-30 · **Status:** draft — awaiting scoping decisions
**Context:** integrate three features INTO the companion (PWA + APK), not external apps.

## 1. QR pairing / auth (Phase 1 — PWA + APK)
- **Share connection (generate):** an already-authenticated companion asks the box
  auth module for a short-lived, single-use PAIRING TOKEN, and renders a QR encoding
  `{box_url, pairing_token, exp}`. Self-contained JS QR encoder (no CDN).
- **Onboard device (scan):** a fresh companion opens "Scanner pour jumeler" → camera
  (`getUserMedia`) → bundled JS QR decoder → posts the pairing token to the box →
  receives a real device token → paired. No manual URL/token typing.
- **Resource flashing:** an authenticated device can also emit a QR for a specific
  resource (service URL + scoped token / deep link) to hand to another device.
- **Box side:** new auth endpoints — mint pairing token (short TTL, single use),
  redeem pairing token → device token. Audit each pairing (CSPN immutable log).

## 2. Optional WireGuard LAN tunnel (Phase 2 — APK only)
- **Purpose:** off-LAN, tunnel into the box LAN so `*.gk2` / 10.x resources resolve.
- **Box side:** the wireguard module issues a companion PEER config (reuse
  secubox-wireguard `wgctl`), returned to the paired device on request.
- **App side — THE PIVOT (embed vs delegate):**
  - (a) DELEGATE: hand the .conf to the official WireGuard app via intent/import.
    Light; not "in the companion".
  - (b) EMBED: a Capacitor plugin wrapping Android VpnService + wireguard-go
    (userspace tun), so a "Tunnel LAN" toggle lives in the companion itself.
    Heavy native work; iOS is a separate NetworkExtension effort (deferred).
- **UX:** a "Tunnel LAN" switch; auto-suggest when the box is unreachable directly
  but reachable via tunnel.

## Constraints / notes
- Companion is self-contained (strict CSP, no CDN) → QR encoder/decoder must be
  bundled JS, camera via getUserMedia in the WebView/PWA.
- APK already exists (in.secubox.companion, Android TV + phone). WG embed = new
  plugin + native build; QR = pure www.
- Deferred: iOS WG (NetworkExtension), multi-box tunnel routing.

## Decisions (2026-07-30)
- WireGuard: PHASED — v1 delegate to official WG app, v2 embed VpnService plugin.
- QR pairing: implement AFTER Jellyfin lands (avoid companion file conflicts).
- QR codes: render with an EMOJI in the centre (branded QR, per-resource emoji).

## Distribution (answer)
- **Direct from companion.gk2.secubox.in = YES, already live** (APK hosted +
  URL-installable). This is the sovereign channel — no Google gatekeeper, fits
  the appliance model. Add a download page + a QR to the .apk for phones, and
  sideload/adb for Android TV (Freebox). RECOMMENDED primary channel.
- **Full offline = YES**: PWA service-worker caches the shell; the APK also
  bundles www as assets, so the UI runs with no network. Live data still needs
  the box reachable (directly on LAN, or via the WG tunnel when remote).
- **Autoconnect = YES**: after first pairing the (URL+token) is stored and the
  app auto-connects on launch; QR pairing removes the typing step on a TV. A
  build can also bake a default box URL so a fleet APK autoconnects out-of-box.
- **Play Store = POSSIBLE, with overhead**: needs a Play Developer account, a
  RELEASE-signed AAB (not debug), privacy policy, target-API + content rating,
  TV quality-tier for Android TV, and review may flag a WebView-wrapper that
  points at a private box (minimum-functionality policy; needs test creds).
  Feasible for reach, but runs against the sovereign ethos — recommend direct
  distribution now, optional Play/AAB later if public reach is wanted.
