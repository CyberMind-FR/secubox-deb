<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Double-Cache Pattern — SecuBox dashboards

> Status: **enforced** by `scripts/check-dashboard-cache.py` via the
> `Dashboard Cache Lint` GitHub Actions workflow.

## TL;DR

If your FastAPI handler in `packages/secubox-*/api/main.py` matches any
of the **hot routes** below *and* reads logs / runs subprocesses / opens
files, it **must** go through a cache. The lint will block the PR
otherwise.

Hot routes :
```
/stats   /alerts   /summary   /dashboard   /metrics   /overview
/events  /history  /recent    /bans        /sessions  /connections
```

## Why

These endpoints are typically polled by dashboards (SOC, Hub, c3box…)
every 5 s. Without a cache, each call does the full work (log scan,
GeoIP lookup, subprocess) → CPU saturation under polling. See live-bench
on `admin.gk2.secubox.in` (2026-05-15) where `secubox-waf` sustained
17 % CPU and 1035 syscalls/sec from a single open SOC tab.

CLAUDE.md says it directly:

> **Toujours** pour les dashboards stats (WAF, CrowdSec, bandwidth, DPI…)
> **Toujours** quand l'endpoint lit des logs ou calcule des agrégats
> **Toujours** quand la donnée peut être périmée de 60s sans impact utilisateur

## How to comply

Three accepted shapes — pick one.

### 1. Read-through cache (preferred — simple, robust)

Mirror `packages/secubox-crowdsec/api/main.py:106-138` (or
`packages/secubox-waf/api/main.py` after PR #146 merges):

```python
import threading, time
from typing import Any, Dict, Optional

class StatsCache:
    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache and time.time() - self._timestamps[key] < self.ttl:
                return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def invalidate(self, key: Optional[str] = None):
        with self._lock:
            if key:
                self._cache.pop(key, None); self._timestamps.pop(key, None)
            else:
                self._cache.clear(); self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=30)


@app.get("/stats")
async def get_stats():
    cached = stats_cache.get("stats")
    if cached is not None:
        return cached
    stats = compute_stats()        # the expensive bit
    stats_cache.set("stats", stats)
    return stats
```

Invalidate explicitly on mutating endpoints :

```python
@app.post("/ban")
async def ban(...):
    do_the_ban()
    stats_cache.invalidate()
    return {...}
```

### 2. Background-refresh task

Spawn a periodic task at startup that pre-warms the cache.

```python
async def refresh_cache():
    while True:
        try:
            _cache.update(await compute_stats())
        except Exception as e:
            log.error("refresh failed: %s", e)
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_cache())
```

This is more code but lets you keep handler bodies trivial. Used by
`secubox-system`, `secubox-publish`, others.

### 3. Pure in-memory handler

If the handler doesn't open files, run subprocesses, or read logs, the
lint won't flag it. Trivial in-memory aggregations from runtime state
are fine without a cache.

## How to add an exception

Only if you genuinely can't comply right now :

```toml
# .cache-lint-allowlist.toml
[[entries]]
daemon = "secubox-myservice"
route = "/stats"
justification = "Reason + issue link. e.g. real-time data, caching would mislead — see #999"
```

Every entry is implicitly a TODO. Drop the entry when you patch the
daemon.

## Running locally

```bash
python3 scripts/check-dashboard-cache.py --report   # full table
python3 scripts/check-dashboard-cache.py --check    # CI mode, rc=1 if violations
python3 scripts/check-dashboard-cache.py --json     # machine-readable
```

Tests :
```bash
python3 -m pytest scripts/tests/test_check_dashboard_cache.py -v
```

## Reference implementation

- Read-through : `packages/secubox-crowdsec/api/main.py:106-138`
- Read-through (after PR #146) : `packages/secubox-waf/api/main.py`
- Background-refresh : `packages/secubox-system/api/main.py` (search for `create_task`)
