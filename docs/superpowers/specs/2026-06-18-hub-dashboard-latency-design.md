<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# hub dashboard latency + clients/rich cap (#644)

- **Date:** 2026-06-18 · **Packages:** `secubox-hub`, `secubox-toolbox` · **Issue:** #644
- **Status:** Design approved (scope chosen: targeted cache fix), pending plan

## Problem (measured live on gk2)
- `GET /api/v1/hub/dashboard` = **9-12 s** every request: on cold/stale cache,
  `_svc()` (main.py:537) falls back to **~16 sequential** `systemctl is-active <svc>`
  calls inside the request.
- `GET /api/v1/hub/public/health-batch` = **3.3 s**: one `systemctl list-units
  secubox-*` over ~111 services, **synchronous + uncached**, blocking the shared
  aggregator loop.
- `GET /admin/clients/rich` (toolbox) = **~180 ms**: #635 geo/UA enrichment of all
  ~51 clients though the UI shows top-5.
- Root: the hub is mounted in the aggregator which doesn't run sub-app lifespans;
  the #619 lazy-start warmer fires but the cold request path is per-module / the
  health-batch path is never cached.

## Fix
### secubox-hub (`api/main.py`)
1. **`_refresh_health_batch()`** (new, sync): one `systemctl list-units secubox-*`
   call + the existing parse → store `_cache["health_batch"] = {modules, count}`
   and stamp `_cache["health_batch_ts"]`. (Extract the parse from the current
   handler.)
2. **`_ensure_services_warm()`** (new, async): if `now - _cache["last_refresh"]
   >= CACHE_TTL*2`, `await asyncio.to_thread(_refresh_services_cache)` and stamp
   `last_refresh`. One batched `is-active -- [all]` call, off the loop.
3. **`/dashboard`, `/status`, `/modules`**: `await _ensure_services_warm()` before
   the `_svc` loop → every `_svc` now hits the warm cache (no per-module fallback).
   Replaces ~16 calls with **1** on a cold cache.
4. **`/public/health-batch`**: serve `_cache["health_batch"]` when fresh
   (`now - health_batch_ts < CACHE_TTL*2`); cold → `await
   asyncio.to_thread(_refresh_health_batch)` then serve. Never sync-blocks.
5. **`_background_cache_refresh`**: add `await
   asyncio.to_thread(_refresh_health_batch)` each cycle so both snapshots stay warm.
   (Keep the existing lazy-start middleware + startup hook.)

### secubox-toolbox (`api.py`)
6. **`admin_clients_rich`**: only geo/UA-enrich the first `ENRICH_LIMIT = 12`
   clients (UI shows top-5; headroom). Beyond that, emit bare fields
   (`device_emoji:"📱"`, empty `device`/`flag`/`country_iso`/`asn_org`). Bounds
   the endpoint to ≤12 cached geo lookups.

## Targets
dashboard 9-12 s → <100 ms (warm) / 1 call (cold); health-batch 3.3 s → <50 ms
(warm) / 1 offloaded call (cold); clients/rich 180 ms → ~15 ms.

## Error handling / rollout
- All systemctl work stays offloaded (`to_thread`) + best-effort try/except;
  stale-but-served beats blocking. Cache misses degrade to one batched call, never
  the 16-call loop.
- No schema/config change. Deploy = rebuild + `dpkg -i` both packages; restart the
  hub portal (it runs in the aggregator — restart `secubox-aggregator` OR the
  hub's own service if standalone; confirm at deploy) + toolbox portal. No mass
  restart.

## Tests
- hub: `_refresh_health_batch` parses canned `list-units` → populates cache;
  `/health-batch` warm-cache path makes NO subprocess call (monkeypatch
  subprocess to raise → still returns cache); `_ensure_services_warm` calls the
  batched refresh once when stale, zero when warm (count calls).
- toolbox: `admin_clients_rich` with >12 clients → clients[12:] have bare fields
  (geo NOT called for them — monkeypatch geo.lookup to count calls ≤12).

## Out of scope
- Aggregator running sub-app lifespans / process isolation (the bigger documented
  effort). This is the bounded targeted fix.
