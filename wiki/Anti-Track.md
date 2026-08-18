<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2

**[EN](Anti-Track)** | [FR](Anti-Track-FR) | **🟡 WALL · 🟣 MIND** | 🔒

> Bloque · Empoisonne · Anonymise — *ta vie privée n'est pas à vendre.*

![Anti-Track v2 — Bloque, Empoisonne, Anonymise](images/anti-track-v2-poster.png)

Anti-Track is the SecuBox privacy layer that runs inside the transparent WAF
(`secubox-toolbox` / mitmproxy). It protects every device on your LAN without any
client-side install: trackers are stopped, fooled, or scrubbed before they ever
profile you.

---

## 🟡 The three layers (WALL)

Every request to a known tracker is handled by one of three actions. The system
**fails safe**: when unsure, it poisons (never breaks a page) rather than blocks.

### 1️⃣ Bloque — pure trackers

Hosts that exist *only* to track (analytics beacons, pixels, data brokers) are
blocked at three depths:

| Depth | Mechanism |
|-------|-----------|
| 🧱 **DNS refuse** | the domain never resolves — cheapest, catches even non-proxied flows |
| 🛑 **IP drop** | nftables drop for IPs that serve *exclusively* trackers (CDN/cloud ranges are allowlisted, never dropped) |
| ✉️ **HTTP 204** | the proxy answers the tracker call with an empty success |

A host is promoted to "pure" only after it is confirmed beacon-only across **≥2
sites**. *Ici, pas de quartier.*

### 2️⃣ Empoisonne — load-bearing trackers

Trackers that also carry needed content (tag managers, CDN-hosted scripts) can't be
blocked without breaking the page. Instead they get a **stable fake identity**: the
client presents fabricated-but-valid cookie values the target accepts, so the
tracker builds a coherent profile of *a person who does not exist*.

- The fake identity is **persistent** ("rémanent") — same fiction every visit, no
  rotation tell that would reveal a blocker.
- It is **per-device, per-tracker**, and never derived from your real data.
- Other signals (referer, UA hints, locale, screen) are degraded in the same flow —
  *des infos bidon pour des pisteurs perdus.*

### 3️⃣ Anonymise — every flow

Always-on hygiene applied to all traffic, including the legitimate first-party site:

- strip operator/carrier headers (`MSISDN`, `x-acr`, `x-wap-*`, `X-Forwarded-For`,
  `Referer` to trackers, re-identification `ETag`s…)
- pin `DNT: 1` and `Sec-GPC: 1`

*Propre, léger, anonyme.*

---

## 🔒 Fort Knox — first-party-only (opt-in)

For sensitive sites you can arm **Fort Knox** per-site: every third-party request is
blocked — tracker or not — leaving only the requested site itself. Maximum surface
reduction. It breaks many normal sites (embeds, CDNs, fonts), so it is **off by
default** and armed site-by-site.

> *Nous ne voyons rien. Nous ne gardons rien. Vous gardez le contrôle.*

---

## 🟢 Configuration (ROOT)

Toggles live in `/etc/secubox/toolbox/filters.json` and hot-reload (no restart):

| Key | Default | Effect |
|-----|---------|--------|
| `privacy_enforce` | `false` | master switch — off = **observe-only** (watch, never act) |
| `privacy_poison` | `true` | forge a stable fake identity for load-bearing trackers |
| `privacy_anonymize` | `true` | always-on header hygiene (DNT/GPC, strip operator headers) |
| `privacy_ip_drop` | `false` | nft-drop exclusive-tracker IPs |
| `privacy_dns_feed` | `true` | feed the learned blacklist into `secubox-dns-guard` |
| `fortknox_sites` | `[]` | per-site first-party-only opt-in list |

**Observe-only first.** Anti-Track deploys *dark*: it watches and learns who tracks
you, you review the findings in the dashboard, then you arm enforcement. *On
regarde, mais on ne conserve pas.*

---

## 🟣 How it learns (MIND)

The blacklist is not a static list — it is learned from your own traffic, hourly:

- **cookie-xsite** — a domain that sets a third-party cookie whose id is reused
  across ≥2 of your sites (the textbook definition of a tracking cookie)
- **opgrade** — operator-grade / data-broker hosts seen cross-site
- **threat-intel** — IOC feeds (ThreatFox, Feodo, SSLBL)

Every block, drop, and poison is written to the immutable audit log
(`/var/log/secubox/audit.log`) with a reason and a TTL, so nothing is permanent and
everything is reviewable.

---

## See also

- [[Android-ToolBox]] — one-tap R3 onboarding for client devices
- [[Browser-Extension]] — tracker cartography in the browser
- Design spec: `docs/superpowers/specs/2026-06-17-anti-tracking-v2-design.md`

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
