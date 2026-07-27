# Fleet Metrics — Centralized + Meshed Node Snapshots — Design

**Date:** 2026-07-27
**Sub-project:** 3/3 of the "auto-centre" trilogy (after Centres & Grants + Remote Config, and Assist — both deployed).
**Modules:** `secubox-annuaire` (op + resolver + verb + publisher timer + `/fleet` panel) — reuses the signed journal + `mesh_sync` substrate.

## Goal

Every node federates a compact, signed **snapshot** of its own state onto the existing annuaire journal; a `/fleet` panel shows the whole gondwana mesh at a glance ("all my boxes at once"). Metrics become both **meshed** (federated over the sovereign signed journal, like NodeRecord/bans) and **centralized** (one fleet view on any node).

## Non-goals (out of scope)

- Rich time-series / historical graphs — those stay in the per-box `secubox-metrics` dashboard and `netdata`.
- Duplicating detailed SOC security events — the SOC keeps its domain; the snapshot carries only a *count* of open alerts.
- Alerting/thresholds — a future iteration.
- High-frequency telemetry — the snapshot is a low-frequency (~60s) state summary, not a firehose.

## Inherited invariants

- Sovereign signed journal: every snapshot op is signed with the node key; the resolver binds to the VERIFIED `entry.author` == `payload.issued_by` (fail-closed — the same author-vs-payload hardening as the `active_grants`/assist fixes). A peer cannot forge another node's snapshot.
- No privileged action in-process; the publisher runs as `secubox` (signs with the box key it already owns), never root.
- Transport is the existing `mesh_sync` over wg-mesh only.
- Double-cache pattern for the local collection (stats-heavy → background refresh + cache file), per the project convention.
- Fail-closed: a malformed or stale snapshot is ignored by the resolver, never trusted.
- Never chown the shared parents.

## Architecture

```
each node (gk2 / c3box / amd64)                       any node's /fleet panel
  secubox-metrics-publish.timer (~60s)
      │ metricsctl publish
      │   • collect vitals   (secubox-metrics cache /var/cache/secubox/metrics)
      │   • module health    (systemctl is-active secubox-*)
      │   • counters         (annuaire: active bans / assist sessions / SOC alerts)
      │   • sign + append  METRIC_SNAPSHOT{node_did,...}  ──┐
      ▼                                                     │  mesh_sync (wg-mesh,
   annuaire journal (Ed25519/BLAKE2b, append-only) ◀────────┘  signed, federates)
      │                                                     
      │  compaction: prune snapshots superseded by a newer one from the same author
      ▼
   aggregator (in-process)  fleet_snapshots(entries) -> {node_did: latest}
      │
      ▼
   /fleet panel: matrix node × (vitals / health / counters), colour-coded, "seen Ns ago"
```

### Components (all in `secubox-annuaire`)

| Unit | Responsibility |
|------|----------------|
| `annuaire/model.py` (extend) | `Op.METRIC_SNAPSHOT`; `MetricSnapshot` model (fixed shape, `extra=forbid`) |
| `annuaire/fleet.py` (new, pure) | `fleet_snapshots(entries) -> {node_did: snapshot}` (last-wins per verified author), `is_stale(snapshot, now, ttl)`, health/colour helpers |
| `annuaire/verbs.py` (extend) | `publish_metric(journal, priv, snapshot_fields)` — sign + append (mirrors `publish_ban`/NodeRecord signing) |
| `annuaire/metrics_collect.py` (new, pure-ish) | `collect_snapshot()` — gather vitals + module health + counters from local sources into the `MetricSnapshot` shape (injectable readers for tests) |
| `sbin/…ctl` `publish` subcommand (extend the annuaire ctl) | `metricsctl publish` = `collect_snapshot()` → `publish_metric()`; honors the opt-in toggle |
| `systemd/secubox-metrics-publish.{service,timer}` (new) | ~60s publisher; `User=secubox` |
| `www/fleet/index.html` + `menu.d/…-fleet.json` + `nginx/fleet.conf` (new) | the `/fleet` panel + menu + static route (aggregator serves the API in-process, like `/centers`) |
| API `/fleet` endpoints (extend the annuaire API) | `GET /fleet` (JWT) → `fleet_snapshots` from the journal in-process |

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
issued_by: str (DID)        # == node_did, == verified author
```

## Data flow & resolution

- **Publish:** the timer runs `metricsctl publish`; `collect_snapshot()` reads the per-box `secubox-metrics` cache for vitals (no re-computation — reuse the existing double-cached values), `systemctl is-active` for module health, and the annuaire resolvers for the counters; `publish_metric` signs a `METRIC_SNAPSHOT` and appends it. It federates via the existing `mesh_sync`.
- **Resolve:** `fleet_snapshots(entries)` walks the journal, keeps the LATEST `METRIC_SNAPSHOT` per verified author (`_author(entry) == payload.issued_by`, else skip — fail-closed), returns `{node_did: snapshot}`. The `/fleet` API calls it in-process (read-only, never crashes → `{}` on error).
- **Present:** the panel renders one row per node, colour-coded (a down module → red, high load → amber), with a "seen Ns ago" freshness derived from `ts`; a snapshot older than a staleness TTL (e.g. 5×publish-interval) is greyed as "stale/offline".

## Bounded growth (append-only journal)

`METRIC_SNAPSHOT` ops carry no durable authority (unlike grants/bans), so they are **compactable**: only the latest per author matters. The design keeps growth bounded by:
1. Low publish frequency (~60s).
2. A **compaction pass** that prunes `METRIC_SNAPSHOT` entries superseded by a newer one from the same author.

The exact compaction mechanism depends on what the annuaire journal supports (whether it can prune/rewrite append-only entries without breaking per-entry signature verification — each entry self-verifies against its own author sig, so dropping a superseded snapshot does not invalidate others). **The implementation plan must verify the journal's compaction capability first**; if the journal cannot prune, the fallback is a dedicated last-wins mesh-synced snapshot store (one current record per node, federated like NodeRecord) instead of appending to the main journal. Either way the resolver contract (`fleet_snapshots -> {node_did: latest}`) is unchanged.

## Sovereignty / consent

A node shares **its own** vitals — a symmetric, opt-in model, not a delegated authority. No `capability` grant is required (unlike config/assist, where a *center* acts *on* a box). Consent is a per-node **publish toggle** (config `[metrics] fleet_publish = true`, default on); when off, the node publishes nothing and simply doesn't appear in others' `/fleet`. Every mesh member sees every published snapshot — a shared fleet view. The resolver's author-binding prevents a peer from forging or overwriting another node's snapshot.

## Error handling

- Publisher: collection failures degrade gracefully (a missing source → that field omitted/zero, snapshot still published); the timer never fails the boot.
- Resolver: fail-closed — malformed/unsigned/foreign-authored snapshots are skipped; stale ones are shown greyed, not hidden (an offline node must be visible as offline).
- Panel: JWT-gated read; `{}` when the journal is unreadable; no in-process privileged action.

## Testing

- `fleet.py` pure: `fleet_snapshots` last-wins per author, author-binding (forged `issued_by` != verified author → skipped), `is_stale` boundary, colour/health helpers. Unit-tested with dict fixtures.
- `metrics_collect.collect_snapshot` with injected readers (fake cache/systemctl/counters) → correct fixed-shape record; graceful on missing sources.
- `publish_metric` signs verifiably (journal.append re-verifies) and round-trips through `fleet_snapshots`.
- ctl `publish` DRYRUN writes nothing; honors the opt-in toggle (off → no append).
- Panel/menu: `sbx_token`, `/shared/sidebar.js`, no inline `on*=`/`innerHTML`, valid menu schema.
- Packaging: publisher unit `User=secubox`; no shared-parent chown; `#DEBHELPER#` alone.

## Deploy notes

Rides the existing `mesh_sync` (no new inter-node transport, no new forwarded port). Publisher enabled by default (opt-in on). The `/fleet` API route may need a manual `webui.conf` location on gk2's admin vhost (the recurring `secubox.d`-dropin-inert gotcha — same as `/releases`), confirmed at deploy.
