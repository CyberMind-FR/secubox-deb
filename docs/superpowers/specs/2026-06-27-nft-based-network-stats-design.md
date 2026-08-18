<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — nft-based network stats into the dashboard (#758)

**Date:** 2026-06-27
**Issue:** [#758](https://github.com/CyberMind-FR/secubox-deb/issues/758)
**Status:** Approved design, pending implementation plan
**Branch:** `feature/758-nft-based-network-stats-log-counter-drop`

---

## 1. Problem

The `#ads` dashboard breakdown (issue #755) exposes a **"Drops réseau"** KPI fed by
`network_drops`, which currently always reads **0**. Its source is an anonymous
inline counter in the `inet secubox_blacklist` `enforce` chain, read via
`nft -j list table inet secubox_blacklist` — and it only covers blacklist /
quarantine drops, which sit at 0 until the blacklist-sync daemon populates the
sets. There is no view of general firewall drops, attack/blocked-traffic
categories, or in/out interface throughput.

This work feeds **real network-layer stats from nftables** (plus interface
counters) into the dashboard: categorized drops, attack/blocked traffic,
ad-blocks (cross-referenced), and in/out throughput — with a 24h time-series and
charts.

## 2. Goals / Non-goals

### Goals
- Real, categorized **drops** and **attacks** sourced from nft **named counters**.
- **In/out** throughput per interface.
- **Time-series** retention (SQLite) powering 24h charts.
- A new **"Réseau"** tab in the toolbox dashboard.
- The existing `#ads` "Drops réseau" KPI becomes real.

### Non-goals (v1)
- No per-flow / per-connection accounting (that is nDPId / metrics territory).
- No injection of named counters into the externally-managed `inet crowdsec`
  table (read-only best-effort instead).
- No new heavy charting dependency if the dashboard already ships one.

## 3. Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| v1 scope | Full dashboard with time-series |
| Ownership | **Hub collects** (reuses its root nft poller + sudoers), **toolbox renders** |
| Instrumentation | **Hybrid** — named nft counters (drops/attacks) + `/proc/net/dev` (in/out) + app-layer `ad_block_stats` (ads) |
| Store | **SQLite** time-series (`/var/lib/secubox/hub/netstats.db`) |
| UI surface | New **"Réseau"** tab in the toolbox dashboard |

## 4. Architecture

```
[kernel nft named counters] ──┐
[/proc/net/dev interfaces]  ──┼─► secubox-netstats-collect      (root oneshot, 30s timer, in secubox-hub)
[inet crowdsec counters (RO)]─┘        │
                                       ├─► SQLite  /var/lib/secubox/hub/netstats.db   (cumulative samples, time-series)
                                       └─► snapshot /var/lib/secubox/hub/netstats.json (latest + instantaneous rates, 0644)
                                                  │
   hub api (user secubox, under aggregator) reads DB/json ──► GET /api/v1/hub/netstats/{summary,series}
                                                  │
   toolbox "Réseau" tab JS ──► fetch /api/v1/hub/netstats/*   (charts + tiles)
   toolbox /admin/ad-stats  ──► reads netstats.json → real network_drops (#ads KPI)
```

**Root/user split.** The collector runs as **root** (oneshot + timer, mirrors the
existing `secubox-nft-cache.timer` pattern in hub) because `nft -j list counters`
needs `CAP_NET_ADMIN`. The hub API and toolbox API run as user `secubox` inside
the aggregator process and only **read** the DB / snapshot file. A new dedicated
collector is used rather than overloading `secubox-nft-cache`, because this one
also does SQLite inserts, `/proc` reads, and crowdsec reads.

## 5. nft instrumentation — named counters

Add **declared named counter objects** to the owning tables and reference them
with `counter name "…"` on the existing drop rules. Naming convention:
`sbx_<category>[_<af>]`.

| Category | Counter(s) | File (owner package) | Change |
|---|---|---|---|
| C2 blacklist drops | `sbx_drop_blacklist_v4`, `sbx_drop_blacklist_v6` | `secubox-blacklist.nft` (secubox-toolbox) | add |
| Quarantine drops | `sbx_drop_quarantine_v4`, `sbx_drop_quarantine_v6` | `secubox-blacklist.nft` (secubox-toolbox) | add |
| DoH/DoT detect | `sbx_doh_detect_v4`, `sbx_doh_detect_v6` | `secubox-blacklist.nft` (secubox-toolbox, `doh_watch`) | add |
| WAF rate-limit (scanners/bots) | `sbx_drop_wafrl` | `secubox-waf-ratelimit.nft` (secubox-mitmproxy) | add |
| Unsolicited inbound (policy drop) | `sbx_drop_input_policy` | **new** `zz-secubox-netstats-tap.nft` (secubox-hub) | add |
| CrowdSec bouncer drops | existing counters in `inet crowdsec` | — | **read-only, best-effort** |

Notes:
- Named counter objects **must be declared in the same table** as the rules that
  reference them (no cross-table counter refs). Each owning `.nft` declares its
  own counters at table scope, then references them inline:
  `ip daddr @blacklist_v4 limit rate 20/second log prefix "SBX-BL-DROP " counter name "sbx_drop_blacklist_v4" drop`.
- The **unsolicited-inbound** tap is a hub-owned drop-in that declares
  `counter inet filter sbx_drop_input_policy` and appends a tail
  `add rule inet filter input counter name "sbx_drop_input_policy"` — a bare
  counter at the end of the default-drop `input` chain counts exactly what the
  policy would drop. It **must load after** all accept rules, hence the `zz-`
  prefix (same ordering precedent as `zz-secubox-toolbox-wg-fanout.nft`).
- `inet crowdsec` is created/regenerated by `crowdsec-firewall-bouncer`; we must
  **not** rewrite it. The collector reads its counters if present and treats them
  as best-effort (0 when absent).
- **Counters reset to 0 on every `nft -f` reload.** The collector and the series
  math are reset-aware (§8).

## 6. Collector + store

**Script:** `/usr/lib/secubox/hub/netstats-collect.py` (Python, shipped by secubox-hub).
**Units:** `secubox-netstats.service` (`Type=oneshot`, root) + `secubox-netstats.timer`
(`OnBootSec=15s`, `OnUnitActiveSec=30s`, `AccuracySec=5s`).

Each tick:
1. `nft -j list counters` → map counter-name → cumulative `{packets, bytes}` per category.
2. `/proc/net/dev` → per-interface `rx_bytes, rx_packets, tx_bytes, tx_packets`.
   Interfaces from hub config (default: all non-`lo`).
3. Best-effort read of `inet crowdsec` counters.
4. INSERT samples into SQLite (cumulative values + `ts`).
5. Write `netstats.json` snapshot: latest cumulative + **instantaneous rates**
   computed vs the previous sample (reset-aware) + `updated` ts.
6. Retention: `DELETE FROM … WHERE ts < now - 7d` (keep a week; charts default 24h).

**SQLite schema** (long-and-narrow, easy to query/downsample; avoids a wide
dynamic-interface table):

```sql
CREATE TABLE IF NOT EXISTS counter_samples (
  ts    INTEGER NOT NULL,
  name  TEXT    NOT NULL,   -- e.g. sbx_drop_blacklist_v4
  packets INTEGER NOT NULL,
  bytes   INTEGER NOT NULL,
  PRIMARY KEY (ts, name)
);
CREATE TABLE IF NOT EXISTS iface_samples (
  ts    INTEGER NOT NULL,
  iface TEXT    NOT NULL,   -- e.g. eth0, br-lan
  rx_bytes INTEGER NOT NULL, rx_packets INTEGER NOT NULL,
  tx_bytes INTEGER NOT NULL, tx_packets INTEGER NOT NULL,
  PRIMARY KEY (ts, iface)
);
CREATE INDEX IF NOT EXISTS idx_counter_ts ON counter_samples(ts);
CREATE INDEX IF NOT EXISTS idx_iface_ts   ON iface_samples(ts);
```

File perms: DB + json written by root, dir `0755`, files `0644` (user `secubox`
reads). DB opened read-only by the API.

## 7. API (secubox-hub, read-only)

- `GET /api/v1/hub/netstats/summary`
  Latest snapshot: per-category cumulative + current rate (pkt/s, bit/s),
  per-interface in/out throughput (bit/s), `updated` ts, `stale` flag.
- `GET /api/v1/hub/netstats/series?window=24h&step=5m&metric=<cat|iface>`
  Downsampled buckets; deltas/rates computed server-side from cumulative
  samples, **reset-aware**.

`network_drops` for the `#ads` KPI = sum of `sbx_drop_*` categories (+ crowdsec
best-effort), read by toolbox from `netstats.json`.

## 8. Correctness / error handling

- **Counter resets:** if a cumulative value is **lower** than the previous
  sample, an `nft -f` reload occurred → that interval's delta = the current value
  (never negative). Same logic for `/proc` interface counters (rare 64-bit wrap /
  iface re-create).
- Each source is wrapped independently: missing counter/table/iface ⇒ 0, logged,
  others proceed.
- Collector down ⇒ API serves last snapshot with `stale: true` + `updated` age;
  frontend renders a staleness badge.
- SQLite write failure ⇒ snapshot still written; error logged to journald.
- Read/write privilege split enforced by file ownership (root writes, secubox
  reads).

## 9. Frontend — new "Réseau" tab (`packages/secubox-toolbox/www/toolbox/index.html`)

- **Throughput chart:** in/out bit/s per interface, 24h (from `/series`).
- **Drops/attacks trend:** stacked-by-category, 24h (from `/series`).
- **Breakdown tiles:** total drops, by category, top sources (from `/summary`).
- **#ads KPI:** "Drops réseau" repointed to the real `network_drops`.
- **Charts:** reuse the dashboard's existing charting lib if present; otherwise a
  lightweight inline SVG sparkline — **no new heavy dependency**. (Confirmed
  during implementation.)
- Staleness badge when `stale: true`.

## 10. Packages touched + deployment

| Package | Change | Bump |
|---|---|---|
| **secubox-hub** | collector script, `.service`+`.timer`, `zz-secubox-netstats-tap.nft`, SQLite schema, API endpoints (sudoers already grants `nft -j list *`) | yes |
| **secubox-toolbox** | `secubox-blacklist.nft` named counters, new "Réseau" tab, repoint `network_drops` | yes |
| **secubox-mitmproxy** | `secubox-waf-ratelimit.nft` named counters | yes |
| secubox-crowdsec | none (read-only) | no |

- Each package's `postinst` reloads its own `.nft` (existing idempotent
  delete+recreate pattern). `nft -c -f` syntax check added in CI for changed/new
  `.nft` files.
- Postinst must preserve runtime state (try-restart for the timer; redeploy
  operator drop-ins) per existing project guidance.

## 11. Testing

- **Unit:** counter-name→category map; `/proc/net/dev` parser; reset-aware
  delta/rate math; SQLite insert + downsample query; snapshot staleness logic.
- **Integration:** one collector run yields rows + valid `/summary` and `/series`
  shapes; graceful when DB / counters / crowdsec table are absent.
- **nft:** `nft -c -f` syntax check on each modified/new `.nft`.

## 12. Open items (resolve during implementation)

- Confirm the dashboard's existing charting approach before choosing chart impl.
- Confirm whether to expose a `forward` policy-drop tap in addition to `input`
  (v1: input only).
- Interface selection: config-driven allow-list vs all-non-`lo` (v1: all-non-`lo`,
  config override available).
