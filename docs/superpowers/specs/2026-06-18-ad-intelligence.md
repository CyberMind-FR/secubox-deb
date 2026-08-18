<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Ad Intelligence — learn · act · measure (contextual) — design

- **Date:** 2026-06-18 · **Package:** `secubox-toolbox` · **Issue:** #656
- **Status:** Design approved (aggressive learning, new #ads tab). Pending plan.

## Goal
Turn `ad_ghost` from a static blocker with global counters into: (1) an
**aggressive ad-URL learner**, (2) a unified **block/silent/drop** actor, (3) a
**contextual metrics** source feeding a new **#ads** dashboard tab.

Safety doctrine (lesson from the splice incident): **learning to BLOCK is
reversible** (a false positive is a blocked resource, fixed via allowlist + made
visible by the new metrics) — unlike learning to bypass. So aggression is OK
*as long as* there's an allowlist + visibility + a kill toggle.

## Today (baseline)
`ad_ghost.requestheaders` 204s hosts matching `_AD_HOST` regex ∪
`learned-trackers.txt` (R3+ only); `response` hook injects cosmetic-hide CSS
(`pages_cleaned`). Metrics = GLOBAL only in `/run/secubox/ghost.json`
(`blocked_requests`, `bytes_saved_est`, `pages_cleaned`, `learned_blocks`). No
per-host / per-site breakdown. `autolearn` grows `learned-trackers.txt` from
opgrade/cookie-xsite/threatfox.

## Architecture

### A. Measure — contextual metrics (the visible deliverable)
- **Store** (`store.py`): `ad_block_stats(ad_host, site, action, hits, bytes,
  last_seen, PRIMARY KEY(ad_host, site, action))`. `action ∈ {block, silent}`
  (drop reserved). Helpers: `record_ad_blocks(rows)` (batch upsert, capped
  per-key), `ad_stats(hours)` (aggregate), `purge_ad_stats(ttl_h)`.
- **Recording** (`ad_ghost`): an in-memory `_ctx` dict keyed `(host, site,
  action)` → `{hits, bytes}`. On each 204 → `_ctx[(host, site, "block")]`
  += (1, EST_BYTES); on each cosmetic-hide → `_ctx[(site, site, "silent")]`
  += (1, 0). `site = registrable(Referer)` (page context; "" if absent).
  In `_flush` (every 5 s) the `_ctx` snapshot is **offloaded to a bg thread**
  (mirror `local_store`/splice — NO SQLite on the request path) → batch upsert,
  then cleared. ghost.json global counters stay (back-compat).
- **API** (`api.py`): `GET /admin/ad-stats?hours=24` (kbin-public-safe, read-only)
  → `{window_hours, total_blocked, total_bytes, by_action:{block,silent},
  top_hosts:[{host,hits,bytes}], top_sites:[{site,hits}]}`.

### B. Act — block / silent / drop
- **block** = 204 (existing). **silent** = cosmetic CSS hide (existing).
- **drop** = nft IP-drop — this is the anti-track `privacy_ip_drop` path
  (`escalate.py`), gated + dark. v1 records the `drop` action in the schema and
  surfaces it in stats, but wiring ad hosts into IP-drop is **deferred** (reuse
  anti-track's escalate; risky/shared-IP — opt-in later). v1 ships block+silent.

### C. Learn — aggressive ad-URL discovery
- **Candidate capture** (`ad_ghost.requestheaders`, gated `ad_learn`): when a
  request is **third-party** (`registrable(host) != registrable(site)`) AND
  matches an **ad-shape** signal — path regex (`/ads?/|/adserver|/pagead|
  /gampad|/doubleclick|/beacon|/pixel|/collect|/track(ing)?|/telemetry|/metric`)
  OR host regex (ad/analytics-ish) — record into `ad_candidates(host, site,
  hits, last_seen)` (in-memory `_cand` dict, flushed with `_ctx`).
- **Promotion** (`autolearn`): `_ad_feed()` promotes candidates seen on
  `>= AD_MIN_SITES` distinct sites (AGGRESSIVE default **1**) → append to
  `learned-trackers.txt` (deduped, registrable-folded, capped), EXCLUDING any
  host in `ad-allowlist.txt`. `ad_ghost` already 204s `learned-trackers.txt`.
- **Allowlist** (`ad_ghost`): load `ad-allowlist.txt` (operator un-block); a
  host/registrable in it is **NEVER** 204'd, even if in `_AD_HOST`/learned —
  allowlist always wins. mtime-cached.
- **Toggle** (`filters.py`): `ad_learn` (bool, default **true**) gates candidate
  capture + promotion. (Distinct from `ad_ghost`/`ad_ghost_block` which gate the
  blocking itself.) `off` stops growing the list (existing entries still block).

### D. #ads dashboard tab (`www/toolbox/index.html`)
- New tab button `data-tab="ads"` (🛑 Pubs / Ads); `switchTab('ads')` →
  `loadAds()`; `loadAds()` fetches `/admin/ad-stats?hours=24` and renders:
  KPIs (total blocked, bytes saved, distinct ad hosts), top ad-hosts table
  (host · hits · KB), ads-per-site table (site · hits), action split
  (block/silent). Mirror `loadSocial`'s escaping + table style.

## Safety / rollout
- **Allowlist always wins** in `ad_ghost` (un-block path).
- **`ad_learn` toggle** to stop aggression; **metrics surface every block** so
  false positives are visible per host/site → operator allowlists them.
- Aggressive default (`AD_MIN_SITES=1`) — env-overridable to tune down fast.
- block-only is reversible (no IP-drop in v1). No CSP/security weakening.
- Deploy = rebuild + rolling restart of the 4 mitm-wg workers (NOT the portal —
  avoid kbin 503) + the portal only if `/admin/ad-stats` is portal-served (it is
  → restart portal too, accept the brief kbin blip, or serve via aggregator).

## Hot-path safety
- `requestheaders` recording = dict increments + one regex + one registrable
  compare; SQLite only in the 5 s bg-thread flush. Never blocks the proxy.
- All recording best-effort try/except — never breaks a flow.

## Tests
- store: `record_ad_blocks` upsert/cap; `ad_stats` aggregation (top hosts/sites,
  by_action, totals); `ad_candidates` capture + `purge`.
- ad_ghost: allowlist host NOT blocked even if in _AD_HOST/learned; 3rd-party
  ad-path request recorded as candidate; first-party not; block records ctx.
- autolearn `_ad_feed`: promotes candidate on ≥AD_MIN_SITES sites, excludes
  allowlisted, dedups.
- filters: `ad_learn` default true, bool-validated.
- api: `/admin/ad-stats` shape (monkeypatch store.ad_stats).

## Files
- `secubox_toolbox/store.py` (tables + helpers), `mitmproxy_addons/ad_ghost.py`
  (ctx/candidate recording + allowlist + bg flush), `secubox_toolbox/api.py`
  (`/admin/ad-stats`), `www/toolbox/index.html` (#ads tab),
  `sbin/secubox-toolbox-autolearn` (`_ad_feed`), `secubox_toolbox/filters.py`
  (`ad_learn`), `conf/` (ship an empty `ad-allowlist.txt`? — operator file under
  /var/lib, created on demand), tests + changelog.
