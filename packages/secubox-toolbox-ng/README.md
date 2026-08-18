<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-toolbox-ng — Go MITM engine (migration spike, #662 Phase 1)

De-risking PoC for migrating the R3 toolbox MITM engine off Python **mitmproxy**
(GIL-bound, ~1 core) onto a multi-core **Go** core, **without losing the
18-addon feature set**. See:
- Analysis: `docs/superpowers/specs/2026-06-18-mitm-engine-migration-analysis.md`
- Phased plan: `docs/superpowers/plans/2026-06-18-mitm-engine-migration.md`

> **Status: Phase 1 — PoC only. NOT wired into the live R3 path.** The live
> tunnel still runs on the Python mitmproxy workers (8081-8084). This binary is
> a standalone CONNECT-proxy spike that proves the risky capabilities.

## What the PoC proves (the discriminating risks from the analysis)
- **CA-compat forging** — loads the *existing* `ca-wg/{ca.pem,key.pem}` and forges
  per-host leaf certs the R3 clients already trust (no re-enroll). Cached per host.
- **request 204** — short-circuit block (ad_ghost / privacy_guard).
- **response body inject** — marker before `</head>`/`</body>` (banner / ad-CSS).
- **SNI splice** — raw passthrough, no MITM, by SNI suffix (tls_splice).
- **JA4 material capture** — `crypto/tls` `GetCertificate` receives the
  `ClientHelloInfo` (SNI, cipher suites, ALPN, TLS versions) → proves the `ja4`
  addon's handshake fingerprint is reachable in Go (full JA4 extension-hash needs
  a raw-ClientHello peek — Phase 4).

All stdlib (no external modules → builds offline). Tests are network-free
(localhost handshake + temp self-signed CA).

## Build & test
```sh
cd packages/secubox-toolbox-ng
go test ./...                                   # network-free PoC tests
GOOS=linux GOARCH=arm64 go build -o sbxmitm ./cmd/sbxmitm   # appliance target
```

## Try it (CONNECT proxy, against the board CA)
```sh
./sbxmitm --ca-cert /etc/secubox/toolbox/ca-wg/ca.pem \
          --ca-key  /etc/secubox/toolbox/ca-wg/key.pem --listen :8090
curl -x localhost:8090 --cacert /etc/secubox/toolbox/ca-wg/ca.pem https://doubleclick.net/   # → 204
curl -x localhost:8090 --cacert /etc/secubox/toolbox/ca-wg/ca.pem https://example.com/        # → body has the sbx-ng marker
# logs print `ja4 t0304_cNN_a... sni=...` per handshake
```

## Capability → engine map (recap)
Go covers request-204 / body-rewrite / header-cookie-mod / splice / async-sidecars
cleanly; JA4 needs the ClientHello shim (proven here); streaming inject + the
anti-track HMAC-jar/poison port land in Phase 3/4. Heavy analysis (social-graph,
classify, DB/report writers) stays in the existing Python sidecars, fed
fire-and-forget over unix sockets.

## Roadmap (do NOT cut over without the gates)
1. ✅ PoC (this) — forge + 204 + inject + splice + ClientHello capture, compiled + tested.
2. arm64 packaging + board bench on :8090 (no DNAT) — forge/throughput vs mitmproxy.
3. Hot-path feature parity (block lists + allowlist + own-infra guard, header/cookie strip, banner, splice) — parity harness vs the Python addons.
4. Analysis sidecars (unix-socket fire-and-forget) + anti-track HMAC-jar/forge port (exhaustively tested vs `privacy.py`).
5. **Shadow run** — mirror a fraction of R3, compare outputs. No client served yet.
6. **Cutover** — flip nft `numgen` fanout 8081-8084 → 8090-8093; mitmproxy stays up for instant rollback.
7. Decommission mitmproxy after a stable soak.

Rollback is an nft DNAT-map edit at every step; the Python engine is the live
path until Phase 6.
