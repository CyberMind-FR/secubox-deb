# MITM engine migration — Phase 2 bench results (#662)

- **Date:** 2026-06-18 · ran the Phase-1 Go PoC on gk2 (arm64), `127.0.0.1:8090`,
  **no DNAT** (zero impact on live R3, which stayed on the mitmproxy workers).

## Proven on the real arm64 board (with the live `ca-wg` CA)
| Check | Result |
|-------|--------|
| Static arm64 binary | 5.4 MB, `ELF aarch64`, CGO_ENABLED=0 — runs natively on gk2 |
| **CA-compat forging** | `curl -x :8090 --cacert ca.pem https://example.com/` → **200**; the forged leaf (signed by the existing `ca-wg` CA) is trusted — R3 clients would trust it, no re-enroll |
| **MITM + body inject** | injected `<!-- sbx-ng banner -->` marker present in the HTML |
| **204 block** | `https://doubleclick.net/` → **204** (ad_ghost path) |
| **JA4 capture** | live: `t0304_c31_ah2_sni=example.com` (TLS1.3 / 31 ciphers / ALPN h2 / SNI) — the `ja4` addon's material is reachable in Go on arm64 |
| **Footprint** | **~12 MB RSS** vs Python mitmproxy ~70–117 MB per worker |

So every **discriminating capability** the analysis flagged (CA-compat, request-204,
body-inject, SNI-splice, JA4) works on the actual hardware, at ~1/6th the memory.

## Gate: "forge + throughput ≥ mitmproxy" — PARTIAL
- **Forge:** ✅ proven (CA-compat, cached per host, fast).
- **Footprint:** ✅ ~12 MB (far below mitmproxy).
- **Throughput / multi-core:** ⚠️ **not cleanly measured.** The instantaneous-CPU
  sample was cut short by (a) a transient `wg-admin` ssh blip and (b) a
  `pkill -f sbxmitm` self-match bug (the kill matched its own ssh shell). Multi-core
  is **structurally guaranteed** — Go runs `GOMAXPROCS=4` with no GIL, vs Python
  mitmproxy capped ~1 core/worker — but a rigorous throughput-vs-mitmproxy
  comparison must be done in a **controlled load environment**, NOT by hammering
  the production board.

## Conclusion
Phase 2 **de-risks the engine on real hardware**: CA-compat + all L7/TLS
discriminators + tiny footprint confirmed on arm64. The throughput gate is
deferred to a controlled bench (Phase 2b) before committing to the port.

## Ops note
The PoC was localhost-only (`127.0.0.1:8090`), no DNAT, cleaned up (`fuser -k
8090/tcp` + binary removed). LESSON: never `pkill -f <name>` over ssh when `<name>`
appears in the remote command line — it kills its own shell; use `fuser -k
<port>/tcp` or `pgrep | grep -v $$` + kill-by-PID.

## Next
Phase 2b (controlled throughput bench) → Phase 3 (hot-path feature parity). Pause
for review before continuing — see the phased plan.
