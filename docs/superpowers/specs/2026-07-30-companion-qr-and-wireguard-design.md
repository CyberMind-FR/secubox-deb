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
