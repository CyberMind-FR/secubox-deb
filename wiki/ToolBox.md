<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# 👁️ ToolBox — the digital phone booth (*cabine numérique*)

> 🟣 **MIND** · 🟡 **WALL** — a public SecuBox access point that shows any
> passer-by, in plain language, exactly what their phone leaks on the network —
> then hands them an ephemeral, anonymous report they can keep.

The **ToolBox** is a self-contained *cabine numérique*: an open Wi-Fi SSID
(e.g. `VILLAGE3B`) on an isolated sandbox subnet, a captive portal with
**explicit R2 consent**, a transparent MITM inspection pipeline, and a live
**privacy report** served at `kbin.<board>.secubox.in`. Nothing is tied to a
real identity — the client MAC is hashed with a daily-rotating salt and all data
expires within 24 h.

- Package: `secubox-toolbox` · FastAPI/Uvicorn portal on `:8088`
- Companion app: [[Android-ToolBox]] 📱 one-tap R3 onboarding
- Doctrine: OPAD + R2-consented egress (CSPN) — no TLS-break without opt-in

---

## Use case — "what is my phone saying about me?"

1. **Connect** to the open `VILLAGE3B` SSID. The captive portal greets you.
2. **Consent (R2)** — one tap *"Activer mon accès"* is the logged opt-in. Without
   it, traffic is relayed but **not** decrypted.
3. **Surf normally.** The cabine classifies your egress (trackers, DPI, cookies,
   TLS fingerprints) in the background — double-buffered, ~60 s windows.
4. **Read your report** — `kbin.<board>.secubox.in/report/me/html`, refreshed
   every 20 s, or **download the PDF** (a faithful copy of the web page).
5. Everything **self-destructs within 24 h**. The report link is an anonymous
   HMAC-sealed token.

Typical settings: a maker-space, a library, a festival stand, a classroom — a
place where people can *see* surveillance capitalism happening on their own
device, with no account and no tracking of their own.

---

## Protection levels (R0 → R3)

| Level | Name | What it does |
|-------|------|--------------|
| **R0** | 🌐 Open | No analysis. Plain relay. |
| **R1** | 🛡 Passive | Passive analysis, no banner (recommended default). |
| **R2** | 🔍 Consented | Analysis **+** in-page transparency banner (explicit TLS-break). |
| **R3** | 🧅 Tunnel | Full WireGuard tunnel (`wg-toolbox`) — mobile clients onboard via the app; the DPI engine sees real egress + media. |

The report's **🔀 Mon niveau de protection** card lets the visitor switch level
live.

---

## The report — *Mon rapport*

The report is the heart of the ToolBox. Same data model in the **live HTML page**
and the **downloadable PDF** — the PDF is a faithful mirror, not a stripped-down
export. Three tabs: **🍪 Pistage**, **🛰️ DPI-Exfil**, **🌍 Overall**.

### 🎮 Netrunner character sheet

A cyberpunk *fiche de personnage* that maps the visitor's live telemetry onto
RPG stats — the friendly face of the analysis:

- **⚡ Caractéristiques** — DÉFENSE / DISCRÉTION / RIPOSTE / INTEL, each shown as
  pips `●●●○○○` with a value and a note (e.g. *"312 pubs tuées"*, *"4 cat · 27 flux"*).
- **🎒 Inventaire · protections** — active defences as ✓/✗ chips (Tor tunnel, MITM
  cert, WireGuard R3, ad-blocker).
- **🐉 Bestiaire · qui te traque** — the top trackers following you across sites.
- **⚔️ Quêtes en cours · menaces** — live threats from the DPI engine, each with
  its **destination and detail** (e.g. `🗡️ NEW CLOUD — AWS S3 · première sortie`,
  `🗡️ BEACONING — Google LLC · 15 flux périodiques (~26.9 s)`), or a *"zone sûre"*
  all-clear.
- **🧬 ICE / Exposition / XP** bars summarise integrity, exposure (0–100), and the
  volume exchanged over 7 days.

### 🍪 Pistage

Verdict-first exposure gauge (0–100) plus *En un coup d'œil*: a **trackers donut**,
a **countries** bar chart (where your data goes), and a **most-tracked-sites** chart.
Deep-technical cards (compromise scoring, threat-intel / DGA / beaconing, contacted
hosts, cookie providers, device fingerprint, cert-pinned apps, inspection
transparency) are collapsed into `<details>`.

### 🛰️ DPI-Exfil — this device's egress (R3)

Four donuts of what *this* device sends out over the tunnel, classified by the DPI
engine: **service categories** (☁️ cloud / 📦 file-host / 💬 messaging / 🤖 AI /
🎬 media / …), **protocols**, **exfiltration alerts**, and **top destinations**, plus
KPIs (flows, ⬆️ Mo sent, ⬇️ Mo received, alerts).

### 🎬 Media types captured

Two complementary views, deliberately distinct:

- **Service category `media`** — streaming *services* recognised by SNI (Netflix,
  YouTube, Spotify…), inside the DPI categories donut.
- **Captured MIME types** — the real `Content-Type` the MITM sees in R4/analyst mode
  (📺 video / 🎵 audio / 🎞️ HLS·DASH manifests / ▶️ video pages), with a top-hosts
  table. Populated once you browse a video/audio through the tunnel.

### 🌍 Overall

The same four DPI donuts aggregated board-wide (all devices behind R3) — for
spotting anomalous usage at the network scale.

---

## Endpoints (public, anonymous)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/report/me/html` | Live HTML report (`?mh=<hash>` for R3/remote clients) |
| GET | `/report/me` | Same report as a PDF |
| GET | `/report/{token}` | HMAC-sealed ephemeral PDF (24 h) |
| POST | `/change-level` | Switch R0/R1/R2 |
| GET | `/wg/toolbox.apk` | Android companion (see [[Android-ToolBox]]) |

All report rendering runs off the event loop, serialized, and short-cached, so a
heavy PDF (or a retry storm) can never wedge the portal.

---

## Privacy & retention guarantees

- **MAC hashing** with a daily-rotating salt — no session ↔ identity mapping kept.
- **R2 = explicit consent only** — the opt-in click is the logged proof; no consent,
  no TLS-break.
- **TLS-break only on the captive subnet** (`10.99.0.0/24`) — the rest of the LAN is
  untouched.
- **24 h retention** — hashes, events, and report links all expire; raw logs are
  dropped at session end.
- **Open by default** — no ads, no resale; a digital commons (CyberMind / Gérald
  Kerma, Savoie).

---

## See also

- [[Android-ToolBox]] — one-tap R3 onboarding companion
- [[Anti-Track]] — the tracker blocking / poisoning / anonymisation engine
- [[Browser-Extension]] — desktop social-graph cartography
- [[Architecture]] — where the ToolBox sits in the six-module stack
