<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — kbin Tor endpoint: quick-switch anonymized web surfing

*Spec · 2026-06-19 · issue [#683](https://github.com/CyberMind-FR/secubox-deb/issues/683) · status: IMPLEMENTED DARK in secubox-toolbox 2.7.1*

> **Implemented (Option A-variant: torify MITM egress).** Switch + tunnel shipped
> default-OFF / fail-closed. Tunnel = nft owner-match on the `secubox-toolbox`
> (mitm-wg) uid → Tor TransPort 9040 / DNSPort 5353; loaded by a root,
> path-triggered reconciler (`secubox-toolbox-tor.path`) so the portal stays
> `NoNewPrivileges=true`. API `GET/POST /admin/tor/*` (kbin-gated) + 🧅 WebUI tab.
> Control/status/NEWNYM reuse secubox-tor's control-port code (`tor_ctl.py`).
> **Granularity is global kbin Tor mode** (owner-match can't be per-client);
> per-client (WG-hash) Tor needs the #662 Go-core SOCKS5 dialer — tracked as a
> follow-up. Before flipping ON: soak + off-board leak test (real board IP must
> never appear); `tls_splice` (#649) should be OFF for torified flows.

## Problem

kbin (the public ToolBoX portal, first tool of the Swiss-army cyber kit) already gives
transparent perf + full-MITM inspection + ad poison/smog + adware-ban banner + safe
browsing. The **egress is still clearnet**: a kbin session exits via the board WAN with the
real IP. The capstone is **anonymity of the exit** — a quick-switch that re-routes a
consenting client's surfing through **Tor** (outbound), turning kbin into a pseudo-network
surfing booth.

This is the **opposite direction** of `secubox-exposure` (which publishes inbound Tor
hidden services). We reuse its Tor control plumbing (bootstrap, NEWNYM) but for egress.

## Invariants (non-negotiable)

1. **Inspection preserved** — Tor sits *after* the MITM forging core, on the upstream
   transport (SOCKS5 dialer). Poison/smog + banner + safe-browsing stay; only the **exit
   IP + network identity** change.
2. **Fail-closed** — if Tor is down/not bootstrapped, traffic is dropped, never falls back
   to clearnet. Anonymity is an invariant, not best-effort.
3. **No DNS leak** — when Tor mode is on, resolution goes through Tor, not local Unbound.
4. **Opt-in, default OFF** — per-client (WG-hash scoped), honors the existing R consent
   level. No silent global toggle.
5. **CSPN** — every Tor on/off decision written to the immutable audit-log; no plaintext
   exit; TLS 1.3 floor unchanged.

## Two transport options (decide first)

| Option | Mechanism | Pros | Cons |
|--------|-----------|------|------|
| **A — SOCKS5 upstream dialer** (preferred) | The Go forging core (#662) dials upstream via Tor's SOCKS5 (`127.0.0.1:9050`) when the client is Tor-flagged. | Clean integration with #662; per-flow choice; cert verify + uTLS preserved; DNS-over-Tor native (SOCKS5 remote resolve). | Requires the Go core to land first (#662 dependency). |
| **B — nft mark → Tor TransPort** | Per-client nft mark routes 80/443 to Tor `TransPort`/`DNSPort`; transparent at L3. | Engine-agnostic; works without #662. | Bypasses the forging core unless chained carefully → risk of losing inspection (violates invariant 1). |

**Recommendation:** Option A, gated on #662 Go core. Option B only as a pre-#662 fallback,
and only if the mark routes *through* the MITM TPROXY first, then Tor.

## Components

- **Tor daemon** — `tor.service`, SOCKS5 `9050` + control port (cookie auth). Reuse
  `secubox-exposure` bootstrap; ensure egress-only config (no relay, no hidden service in
  this profile).
- **toolbox API** — `POST /admin/tor/{on,off}` (per-client, kbin-gated for bulk),
  `GET /tor/state` (bootstrapped? exit country? client flag?), `POST /tor/newnym`.
- **Go forging core (#662)** — upstream dialer switch: Tor-flagged client → SOCKS5 dialer
  (remote DNS) instead of direct. uTLS Chrome FP + manual cert verify unchanged.
- **State store** — per-client `tor_enabled` (WG-hash scoped, TTL-bound) in the toolbox
  SQLite (`clients` table extension or a small `tor_flags` table).
- **nft leak-guard** — when a client is Tor-flagged, a guard rule ensures no 80/443 path
  reaches the WAN except via the Tor dialer (defense-in-depth for invariant 2/3).
- **kbin UI** — 🧅 toggle + state badge (bootstrapping / on / exit-country flag) + "new
  identity" button; respects R-level (greyed if R0).

## UX

```
[kbin page] ── tap 🧅 ──▶ POST /admin/tor/on (this client)
                          ▼
          Tor bootstrapped? ──no──▶ "Tor démarre…" (spinner, fail-closed until ready)
                          │yes
                          ▼
          flag client tor_enabled (WG-hash, TTL 24h) + audit-log
                          ▼
          forging core dials upstream via SOCKS5 → exit IP changes
                          ▼
          badge: 🧅 ON · 🌍 <exit-country flag>   [Nouvelle identité]
```

## Open questions (resolve next session)

- Per-flow vs per-session Tor? (start per-session/per-client; per-flow later)
- Exit-country selection (`ExitNodes {cc}`) exposed to user, or auto?
- Latency expectation messaging — Tor is slower; the perf banner must set expectations.
- Interaction with `tls_splice` (#649): splice = direct fast-path; in Tor mode, splice
  must be disabled or also routed through Tor (else asset flows leak the real IP).
  **Likely: Tor mode forces splice OFF for that client.**
- Interaction with Anti-Track v2 IP-drop/DNS-refuse: ordering vs Tor resolution.

## Dependencies & sequencing

1. **#662 Go core** lands the upstream dialer abstraction → enables Option A.
2. Tor egress profile in `secubox-exposure` (or a dedicated `tor-egress` unit).
3. toolbox API + state + UI.
4. nft leak-guard + DNS-over-Tor verification (leak test: compare exit IP + DNS resolver).
5. CSPN audit-log wiring + soak DARK (flag exists, UI hidden) → flip.

## Test plan (sketch)

- Leak test: with Tor mode on, `check.torproject.org` confirms Tor; DNS resolver is not the
  local Unbound; real WAN IP never observed upstream.
- Fail-closed test: stop `tor.service` mid-session → traffic drops, no clearnet egress.
- Inspection test: ad-block + banner + poison still fire while on Tor.
- NEWNYM test: exit IP changes after "new identity".

---

*CyberMind — Gérald Kerma · LicenseRef-CMSD-1.0*
