<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox MITM engine migration — phased plan (#662)

> Engine: **Go hot-path core + retained Python analysis sidecars** (see analysis doc).
> Discipline: shadow-run before cutover; nft-DNAT flip = instant rollback at every step; NEVER big-bang. This is a multi-PR epic — each phase is its own PR with a gate.

## Invariants (must hold every phase)
- Reuse the existing CA `/etc/secubox/toolbox/ca-wg/{ca.pem,key.pem}` (what R3 clients already trust) — no new CA, no client re-enroll.
- Live R3 keeps running on the Python mitmproxy workers (8081-8084) until the final cutover. The Go core runs on **separate ports (8090-8093)**, no DNAT, until Phase 6.
- Ad-blocking + anti-track must never regress (the whole point of the appliance).
- arm64; one static Go binary; systemd `secubox-toolbox-ng-worker@N`.

## Phase 1 — PoC (THIS PR) — GATE: compiles + smoke test passes
**packages/secubox-toolbox-ng/** (Go module). NOT wired to live R3.
- `go.mod`, `cmd/sbxmitm/main.go`: a forging MITM that loads `ca-wg/{ca.pem,key.pem}`, listens on a port, and demonstrates the discriminating capabilities:
  - request short-circuit **204** for a sample ad host (proves ad_ghost block),
  - response **body inject** of a marker (proves banner/ad CSS),
  - **SNI splice** passthrough for a sample host (proves tls_splice),
  - **JA4 ClientHello capture** via a `crypto/tls` shim logging cipher suites/exts (proves the Go JA4 gap is closable).
- Smoke test (`make test` / a shell script): build for host, run, `curl -x`/transparent a request through it, assert the 204 + the injected marker + a JA4 line.
- `README.md`: build (`GOOS=linux GOARCH=arm64 go build`), the capability map, and the phase roadmap.
- **No deb packaging, no board deploy, no DNAT.** Pure de-risking spike.

## Phase 2 — arm64 build + board bench (no traffic) — GATE: forge+throughput ≥ mitmproxy
- CI/build: cross-compile arm64 static binary; debian packaging stub `secubox-toolbox-ng` (binary + systemd unit, unit DISABLED).
- Deploy the binary to gk2, run on :8090 (no DNAT). Bench: cert-forge latency (cold/warm), req/s, multi-core CPU under synthetic load vs a mitmproxy worker. Confirm it reuses ca-wg certs (client trusts forged leaf).

## Phase 3 — hot-path feature parity — GATE: parity tests green
Port the cheap per-request rewrites into the Go core, reading the SAME data files:
- block 204 from `_AD_HOST`-equivalent + learned-trackers.txt + pure-trackers.txt, with `ad-allowlist.txt` + own-infra guard (#658) honored.
- header/cookie strip (utiq/protective/anonymize), XFF.
- serve `/__toolbox/loader.js` + `/__toolbox/bundle`; banner inject (buffer + streaming).
- SNI splice from the media seed + learned-splice (the safe, no-auto-promote version).
- Parity harness: feed recorded request/response fixtures to both engines, diff the block/inject/strip decisions.

## Phase 4 — analysis sidecars + anti-track poison — GATE: sidecar contract tests
- Go core fires unix-socket events (fire-and-forget) to the EXISTING Python services for social-graph / dpi / cookies / avatar / soc / ja4-scoring — reuse their socket contracts; they stay Python, off the hot path.
- Port the deterministic anti-track **HMAC jar + Set-Cookie forge** to Go (small, security-critical → exhaustive tests vs the Python `privacy.py` jar output for identical inputs).
- Contextual ad metrics (ad_block_stats / per-visitor) written by a sidecar or the Go core's bg writer.

## Phase 5 — SHADOW run — GATE: N-day output parity, zero client breakage
- Run the Go core on :8090-8093. Mirror a SMALL fraction of R3 (e.g. one fanout slot, or a passive tee) to it; compare its would-block/would-inject/recorded against the live mitmproxy for the same flows. Do NOT serve clients from it yet.
- Soak; review divergences; fix; repeat until parity.

## Phase 6 — CUTOVER — GATE: soak, instant rollback ready
- Flip the nft `numgen inc mod 4` fanout from 8081-8084 (mitmproxy) → 8090-8093 (Go core). Keep the mitmproxy workers RUNNING (stopped from receiving DNAT, but up) so rollback = flip the map back (seconds).
- Soak under real load; watch ad-blocking, banner, anti-track, JA4, latency, CPU.

## Phase 7 — decommission — GATE: stable post-cutover window
- Stop/disable the mitmproxy workers; keep the package installed (rollback) for one release, then remove.

## Rollback
At every phase the live path is the mitmproxy workers until Phase 6's DNAT flip; Phase 6 rollback is an nft map edit (seconds). No phase removes the fallback until Phase 7.

## Effort/risk (honest)
Weeks across 7 PRs. Highest-risk areas: JA4-in-Go (de-risked in Phase 1), the anti-track poison port (Phase 4, exhaustively tested), and the cutover (Phase 6, shadow-gated + instant rollback). Recommend pausing after each gate for review.
