<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox MITM engine migration — analysis (gomitmproxy / martian·goproxy / hudsucker / Squid+ICAP)

- **Date:** 2026-06-18 · **Issue:** #662 · **Status:** analysis + recommendation

## Why
The R3 path runs Python **mitmproxy**: GIL-bound, ~1 core total across 4 workers,
the tunnel's CPU/latency ceiling (#646). Goal: a multi-core engine **without
losing the 18-addon feature set**. TLS termination was never the bottleneck —
the single-thread L7 work is — so a bare TLS proxy is a non-starter (loses every
feature). The only worthwhile target is a faster **L7 engine** that re-implements
the inline logic.

## The real requirement: our 18 addons' capabilities
| # | Addon | Capability it needs |
|---|-------|---------------------|
| 1 | inject_xff | requestheaders: set XFF from real peer IP |
| 2 | utiq_defense | requestheaders: detect/strip operator (Utiq) headers; short-circuit |
| 3 | protective_mode | requestheaders: strip tracker headers/cookies, spoof |
| 4 | privacy_guard (anti-track v2) | **request 204 / forge Set-Cookie (HMAC jar) / strip headers**; classify; file+key reads |
| 5 | ad_ghost | request **204** + candidate/per-visitor capture; response **CSS body inject**; allowlist; bg SQLite |
| 6 | media_cache | response synthesis from disk cache (range) |
| 7 | local_store | **tls_clienthello** read + async SQLite |
| 8 | social_graph | response cookie-id correlation + **body peek** + SQLite |
| 9 | inject_banner | request short-circuit **serve** /__toolbox/*; **streaming** body inject + buffered inject; CSP detect |
| 10 | dpi | async fire-and-forget POST (unix socket) |
| 11 | cookies | response Set-Cookie read → async POST |
| 12 | avatar | UA → async POST |
| 13 | ja4 | **raw TLS ClientHello** (cipher suites, extensions, ALPN) |
| 14 | soc_relay | events → async POST |
| 15 | cert_pin_detect | **TLS handshake-error** hook → learn ignore_hosts |
| 16 | media_stats | response headers → stats |
| 17 | tls_splice | **tls_clienthello SNI → connection passthrough** (ignore_connection) |
| 18 | (dpi dup/util) | — |

Capability buckets that discriminate the engines:
- **(C)** request short-circuit (return 204/synth without upstream) — ad_ghost, privacy_guard, inject_banner, media_cache.
- **(E)** **streaming** response body rewrite (inject into first chunk, no buffering) — inject_banner TTFB path.
- **(G)** **raw ClientHello introspection** for JA4 — ja4, local_store.
- **(H)** **TLS-layer SNI passthrough/splice** — tls_splice, cert_pin_detect, bypass list.
- **(I)** TLS handshake-error hook — cert_pin_detect.
- **(J)** async side-effects (socket POST / bg SQLite) — 7 addons.

## Engine assessment

### gomitmproxy (Go, AdguardTeam) — DROP
Purpose-built for ad-blocking MITM, but **last release v0.2.1 (2021), effectively
unmaintained**. Reusing an abandoned TLS-handling core for a security appliance
is the wrong bet. Cross off.

### martian (Google) / goproxy (elazarl) — Go, maintained
- Strong on **B/C/D/F/J** (modifier/handler APIs return custom responses, modify
  headers/cookies/body; goroutines for async). Easy **arm64 cross-compile**
  (`GOOS=linux GOARCH=arm64`), single static binary — great fit for the appliance.
- **Gaps:** **(G) JA4** — both abstract TLS at the HTTP layer; raw ClientHello
  isn't exposed by the modifier API. *Workaround:* wrap the listener with our own
  `crypto/tls` `Config.GetConfigForClient`/`GetCertificate` to capture the
  ClientHello before handing to the proxy — feasible, extra code. **(E) streaming
  inject** is manual (wrap the response body reader). **(H/I)** host-level
  splice/cert-error handling is doable at the CONNECT layer.
- Verdict: pragmatic, lowest-friction toolchain, but JA4 + streaming need custom
  glue.

### hudsucker (Rust, omjadas + ideamans fork) — maintained
- **Best technical coverage:** tokio/hyper async (**multi-core**), `HttpHandler`
  (C/D/F), **streaming bodies (E)** native, WebSocket. Critically, **rustls
  exposes the ClientHello** (Acceptor/`ClientHello` peek pre-handshake) → **JA4
  (G) is clean**, and SNI-based **splice (H)** is natural.
- **Costs:** Rust **arm64 cross-compile friction** (no toolchain here; needs
  `cross`/musl setup), and porting 18 addons + the anti-track HMAC-jar/classify
  brain to Rust is the **highest re-implementation + re-validation effort**.
- Verdict: technically the strongest (only one covering JA4 + streaming cleanly),
  but the heaviest port + ops.

### Squid + ssl-bump + ICAP — mature C, multi-process
- **Native wins:** ssl-bump forges from one root key (A), **peek-and-splice (H)
  is literally tls_splice + the bypass list**, native cert-error handling (I),
  multi-process scaling. ICAP REQMOD/RESPMOD covers **C/D/F** (204, body rewrite,
  header/cookie mod) — ad_ghost/banner-buffer/poison can live in an ICAP service.
- **Gaps:** **(E) streaming** inject — ICAP buffers, no first-chunk inject.
  **(G) JA4** — ICAP is post-decrypt HTTP; ClientHello isn't exposed to ICAP
  (Squid logs its own TLS details, not via ICAP). Heavy **ops/config**; each ICAP
  call is a round-trip; the anti-track HMAC-jar/poison + social-graph logic in an
  ICAP service is awkward (still Python, still off-core for analysis).
- Verdict: least *custom proxy* code + native splice/cert handling, but loses
  JA4 + streaming-banner and trades Python addons for Squid-config + an ICAP
  service. Good if we drop JA4/streaming; otherwise a poor fit.

## Recommendation — **Go hot-path core + retained Python analysis sidecars** (hybrid)
Single-engine "rewrite everything in Rust" is the highest risk; Squid loses JA4 +
streaming. The lowest-risk path to multi-core that **preserves the
security-validated Python brain**:

1. **Go core** (goproxy/martian or a thin `net/http`+`crypto/tls` forging proxy)
   owns the **hot path**: TLS forge (reusing `ca-wg`), SNI splice (H), the cheap
   per-request rewrites — block 204 (ad_ghost/privacy_guard), header/cookie strip
   (utiq/protective/anonymize), banner inject (E via body-reader wrap), serve
   /__toolbox/*. Multi-core, one static arm64 binary.
2. **JA4 (G)** in Go via a `crypto/tls` ClientHello-capture shim (no Python).
3. **Heavy/off-path analysis stays Python sidecars** the Go core feeds
   fire-and-forget over unix sockets (J): social-graph correlation, classify,
   DB/report writers, SOC/DPI relays. These are already async + off the hot path,
   so they don't need to be fast — and we DON'T re-validate the anti-track
   HMAC-jar/poison + cookie-graph security logic in a new language.
4. The anti-track **poison** (forge Set-Cookie from the HMAC jar) is hot-path +
   security-critical → port the *deterministic* jar/forge to Go (small, testable),
   keep classify (which list a host is on) as data the Go core reads from the
   learned/pure files (already file-based).

This gets multi-core on the hot path, keeps the risky brain in validated Python,
and only ports the small, mechanical, hot pieces. If JA4-in-Go proves painful, the
fallback is **hudsucker** (Rust) for the core (clean JA4) at higher port cost.

## Honest effort/risk
- **Weeks, multi-PR.** 18 addons; security-critical; production board.
- Must **shadow-run** the new core alongside mitmproxy (mirror a fraction of R3
  traffic) and compare before any cutover. **Never** big-bang.
- Rollback = the nft fanout still points at the mitmproxy workers until the final
  cutover flips the DNAT to the Go core's ports.

See the phased plan: `docs/superpowers/plans/2026-06-18-mitm-engine-migration.md`.
