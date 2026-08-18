<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Fleet Metrics — Centralized + Meshed Node Snapshots — Design

**Date:** 2026-07-27
**Sub-project:** 3/3 of the "auto-centre" trilogy (after Centres & Grants + Remote Config, and Assist — both deployed).
**Modules:** `secubox-annuaire` (op + resolver + verb + publisher timer + `/fleet` panel) — reuses the signed journal + `mesh_sync` substrate.

## Goal

Every node maintains a compact, **signed current snapshot** of its own state in a dedicated last-wins store; peers pull each other's current snapshot over the existing gondwana mesh listener (`<mesh_ip>:8799`); a `/fleet` panel shows the whole mesh at a glance ("all my boxes at once"). Metrics become both **meshed** (each snapshot is Ed25519-signed by the node key and pulled peer-to-peer over wg-mesh) and **centralized** (one fleet view on any node).

## Transport decision (why NOT the journal)

The annuaire journal is a **BLAKE2b-chained, append-only, immutable SQLite log** (CSPN audit posture — no UPDATE/DELETE; `verify_chain()` detects tampering). Appending a 60s metric snapshot as a journal op would grow the immutable security-audit log **unboundedly** and could never be pruned (deleting any entry breaks the chain). Therefore fleet snapshots do **NOT** live in the journal. Instead each node keeps exactly **one current signed snapshot** (overwritten each publish → bounded to 1 record/node), and the fleet resolver **pulls** each peer's current snapshot over the existing `:8799` mesh read-path and verifies its signature. Sovereignty/author-binding are preserved (Ed25519 sig by the node key, verified `signer_did == node_did`); the CSPN journal stays clean.

## Non-goals (out of scope)

- Rich time-series / historical graphs — those stay in the per-box `secubox-metrics` dashboard and `netdata`.
- Duplicating detailed SOC security events — the SOC keeps its domain; the snapshot carries only a *count* of open alerts.
- Alerting/thresholds — a future iteration.
- High-frequency telemetry — the snapshot is a low-frequency (~60s) state summary, not a firehose.

## Inherited invariants

- Sovereign signing: every snapshot record is Ed25519-signed with the node key; the resolver verifies the sig AND binds identity to the VERIFIED signer — `signer_did == node_did == issued_by` (fail-closed — the same author-vs-payload hardening as the `active_grants`/assist fixes). A peer cannot forge or overwrite another node's snapshot (each node serves only its OWN signed self-snapshot; a pulled snapshot claiming did X but signed by key Y is rejected).
- No privileged action in-process; the publisher runs as `secubox` (signs with the box key it already owns), never root.
- Transport is a peer pull over wg-mesh only, via the existing `:8799` gondwana mesh read-path (same allow-10.10.0.0/24 + deny-all posture as `mesh_sync`). No new inter-node port.
- Double-cache pattern for the local collection (stats-heavy → background refresh + cache file), per the project convention.
- Fail-closed: a malformed or stale snapshot is ignored by the resolver, never trusted.
- Never chown the shared parents.

## Architecture

```text
each node (gk2 / c3box / amd64)
  secubox-metrics-publish.timer (~60s)
      │ metricsctl publish   (honors the [metrics] fleet_publish opt-in)
      │   • collect vitals   (secubox-metrics cache /var/cache/secubox/metrics)
      │   • module health    (systemctl is-active secubox-*)
      │   • counters         (annuaire: active bans / assist sessions / SOC alerts)
      │   • sign  MetricSnapshot{node_did,...}  → OVERWRITE fleet/self.json (bounded, 1/node)
      ▼
   :8799 gondwana mesh read-path  GET /fleet/self  →  serves the local signed self.json

any node's /fleet view:
   fleet.collect(self.json + pull each peer's :8799 /fleet/self over wg-mesh)
      │  verify each sig; keep only signer_did == claimed node_did (fail-closed)
      ▼
   fleet_snapshots -> {node_did: snapshot}   (self + verified peers; unreachable peer = last-known/stale)
      ▼
   /fleet panel: matrix node × (vitals / health / counters), colour-coded, "seen Ns ago"
```

### Components (all in `secubox-annuaire`)

| Unit | Responsibility |
|------|----------------|
| `annuaire/model.py` (extend) | `MetricSnapshot` model (fixed shape, `extra=forbid`) — a standalone signed record, NOT a journal op (no new `Op`) |
| `annuaire/fleet.py` (new, pure) | `sign_snapshot(priv, fields) -> dict` / `verify_snapshot(rec) -> bool` (sig + `signer_did==node_did`, fail-closed); `fleet_snapshots(self_rec, peer_recs) -> {node_did: snapshot}` (verify each, keep verified); `is_stale(snapshot, now, ttl)`; health/colour helpers |
| `annuaire/metrics_collect.py` (new, pure-ish) | `collect_snapshot()` — gather vitals + module health + counters from local sources into the `MetricSnapshot` shape (injectable readers for tests) |
| `annuaire/fleet_store.py` (new) | write/read the local signed self-snapshot at `/var/lib/secubox/annuaire/fleet/self.json` (atomic overwrite, last-wins) |
| mesh `:8799` read-path `GET /fleet/self` (extend the gondwana listener) | serves the local signed `self.json` verbatim (signed → safe to serve publicly on the mesh) |
| `sbin/…ctl` `publish` subcommand (extend the annuaire ctl) | `metricsctl publish` = `collect_snapshot()` → `sign_snapshot()` → `fleet_store.write()`; honors the opt-in toggle |
| `systemd/secubox-metrics-publish.{service,timer}` (new) | ~60s publisher; `User=secubox` |
| `www/fleet/index.html` + `menu.d/…-fleet.json` + `nginx/fleet.conf` (new) | the `/fleet` panel + menu + static route (aggregator serves the API in-process, like `/centers`) |
| API `/fleet` endpoint (extend the annuaire API) | `GET /fleet` (JWT) → reads local `self.json` + pulls each mesh peer's `:8799/fleet/self` (injected fetch, short timeout) → `fleet_snapshots` |

## Snapshot shape

`MetricSnapshot` (fixed, `extra=forbid`):
```
node_did: str (DID)         # whose box
hostname: str               # human label
ts: str (RFC3339 Z)         # when collected
cpu_pct: float              # 0-100
mem_pct: float
disk_pct: float             # root/data max
load1: float
uptime_s: int
modules_up: int
modules_down: list[str]     # names of down secubox-* units (bounded, e.g. cap 20)
counters: {bans: int, assist_sessions: int, soc_alerts: int}
issued_by: str (DID)        # == node_did (the box's own identity)
sig: str                    # Ed25519 over canonical_bytes(record_without_sig/signer_did)
signer_did: str             # derived from the signing key; MUST equal node_did on verify
```

## Data flow & resolution

- **Publish:** the timer runs `metricsctl publish` (skips silently when `fleet_publish` is off); `collect_snapshot()` reads the per-box `secubox-metrics` cache for vitals (no re-computation — reuse the existing double-cached values), `systemctl is-active` for module health, and the annuaire resolvers for the counters; `sign_snapshot()` Ed25519-signs the record; `fleet_store.write()` **atomically overwrites** `fleet/self.json` (last-wins — one record).
- **Serve:** the `:8799` gondwana mesh read-path serves `GET /fleet/self` = the local signed `self.json` verbatim (it is signed, so serving it to mesh peers leaks nothing forgeable).
- **Resolve:** the `/fleet` API reads the local `self.json` and pulls each mesh peer's `:8799/fleet/self` (short timeout, injected fetch for tests); `fleet_snapshots` **verifies each record's sig and that `signer_did == node_did`** (fail-closed — a record failing verification, or claiming a did it didn't sign, is dropped), returns `{node_did: snapshot}`. Read-only, never crashes → partial/`{}` on error; an unreachable peer yields no fresh record and shows as stale.
- **Present:** the panel renders one row per node, colour-coded (a down module → red, high load → amber), with a "seen Ns ago" freshness from `ts`; a snapshot older than a staleness TTL (e.g. 5×publish-interval) is greyed as "stale/offline".

## Bounded by design

Each node holds exactly **one** current snapshot, overwritten in place each publish — storage is O(number of nodes), not O(time). The immutable CSPN journal is never touched. No compaction/pruning problem exists.

## Sovereignty / consent

A node shares **its own** vitals — a symmetric, opt-in model, not a delegated authority. No `capability` grant is required (unlike config/assist, where a *center* acts *on* a box). Consent is a per-node **publish toggle** (config `[metrics] fleet_publish = true`, default on); when off, the node publishes nothing and simply doesn't appear in others' `/fleet`. Every mesh member can pull every node's published snapshot — a shared fleet view. Forgery/overwrite is prevented structurally: a node serves only its OWN signed `self.json`, and the resolver drops any pulled record whose sig fails or whose `signer_did != node_did`, so a malicious peer cannot publish a snapshot under another node's identity.

## Error handling

- Publisher: collection failures degrade gracefully (a missing source → that field omitted/zero, snapshot still published); the timer never fails the boot.
- Resolver: fail-closed — malformed/unsigned/foreign-authored snapshots are skipped; stale ones are shown greyed, not hidden (an offline node must be visible as offline).
- Panel: JWT-gated read; `{}` when the journal is unreadable; no in-process privileged action.

## Testing

- `fleet.py` pure: `fleet_snapshots` last-wins per author, author-binding (forged `issued_by` != verified author → skipped), `is_stale` boundary, colour/health helpers. Unit-tested with dict fixtures.
- `metrics_collect.collect_snapshot` with injected readers (fake cache/systemctl/counters) → correct fixed-shape record; graceful on missing sources.
- `sign_snapshot`/`verify_snapshot` round-trip: a signed record verifies; a tampered field or a record whose `signer_did != node_did` fails (fail-closed); `fleet_snapshots` drops forged/foreign-signed peer records and keeps verified ones.
- ctl `publish` DRYRUN writes nothing; honors the opt-in toggle (off → no self.json write).
- `/fleet` API with an injected peer-fetch: assembles self + verified peers; an unreachable/timing-out peer degrades to stale, never crashes.
- Panel/menu: `sbx_token`, `/shared/sidebar.js`, no inline `on*=`/`innerHTML`, valid menu schema.
- Packaging: publisher unit `User=secubox`; no shared-parent chown; `#DEBHELPER#` alone.

## Deploy notes

Reuses the existing `:8799` gondwana mesh listener (allow-10.10.0.0/24 + deny-all) for the peer pull — no new inter-node port, no new Freebox forward. Publisher enabled by default (opt-in on). The `/fleet` API route may need a manual `webui.conf` location on gk2's admin vhost (the recurring `secubox.d`-dropin-inert gotcha — same as `/releases`), confirmed at deploy. The plan must locate the `:8799` listener's server code to add the `/fleet/self` read-path.
