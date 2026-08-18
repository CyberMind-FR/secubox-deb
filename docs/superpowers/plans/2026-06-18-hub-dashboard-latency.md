<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Hub Dashboard Latency Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the hub `/dashboard`, `/status`, `/modules` (9-12 s) and `/public/health-batch` (3.3 s) into cache-served sub-100 ms responses, and cap the toolbox `/admin/clients/rich` enrichment to the displayed rows.

**Architecture:** Both hub portals run mounted in `secubox-aggregator` (no sub-app lifespan → cold caches). Fix the cold path: dashboard/status/modules `await` ONE batched `systemctl is-active` (warm-on-demand) instead of ~16 per-module calls; health-batch serves a TTL snapshot built by the existing background loop, cold-miss = ONE offloaded `list-units`. Toolbox bounds geo/UA enrichment to the first 12 most-recent clients.

**Tech Stack:** FastAPI, asyncio, systemctl, pytest + monkeypatch.

---

### Task 1: Hub — `_ensure_services_warm()` + health-batch snapshot helper

**Files:**
- Modify: `packages/secubox-hub/api/main.py`
- Test: `packages/secubox-hub/tests/test_cache_warm.py` (create)

- [ ] **Step 1: Write failing tests**

Create `packages/secubox-hub/tests/test_cache_warm.py`:

```python
import asyncio
import importlib
import sys
from pathlib import Path

import pytest

# Import the hub app module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")


def _reset_cache():
    main._cache["services"] = {}
    main._cache["last_refresh"] = 0
    main._cache["health_batch"] = None
    main._cache["health_batch_ts"] = 0


def test_ensure_services_warm_refreshes_when_cold(monkeypatch):
    _reset_cache()
    calls = {"n": 0}

    def fake_refresh():
        calls["n"] += 1
        main._cache["services"]["secubox-x"] = {"name": "secubox-x", "active": True, "socket": False}

    monkeypatch.setattr(main, "_refresh_services_cache", fake_refresh)
    asyncio.run(main._ensure_services_warm())
    assert calls["n"] == 1
    assert main._cache["last_refresh"] > 0


def test_ensure_services_warm_skips_when_fresh(monkeypatch):
    _reset_cache()
    main._cache["last_refresh"] = main.time.time()
    calls = {"n": 0}
    monkeypatch.setattr(main, "_refresh_services_cache", lambda: calls.__setitem__("n", calls["n"] + 1))
    asyncio.run(main._ensure_services_warm())
    assert calls["n"] == 0


def test_refresh_health_batch_parses_units(monkeypatch):
    _reset_cache()

    class R:
        stdout = (
            "secubox-hub.service loaded active running Hub\n"
            "secubox-dpi.service loaded active exited DPI\n"
            "secubox-cdn.service loaded failed failed CDN\n"
        )

    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: R())
    # No sockets present for these in the test env.
    main._refresh_health_batch()
    hb = main._cache["health_batch"]
    assert hb["modules"]["hub"]["status"] == "ok"
    assert hb["modules"]["dpi"]["status"] == "warn"
    assert hb["modules"]["cdn"]["status"] == "error"
    assert main._cache["health_batch_ts"] > 0
```

Run: `cd packages/secubox-hub && python -m pytest tests/test_cache_warm.py -v`
Expected: FAIL (`_ensure_services_warm` / `_refresh_health_batch` not defined; `health_batch` key missing).

- [ ] **Step 2: Add cache keys**

In `main.py`, extend the `_cache` dict literal (currently lines ~322-327):

```python
_cache = {
    "services": {},       # module_id -> {name, active, socket}
    "menu": None,         # Full menu response
    "system_stats": {},   # CPU, memory, disk
    "last_refresh": 0,
    "health_batch": None, # {modules: {...}, count: int} snapshot for sidebar LEDs
    "health_batch_ts": 0, # monotonic-ish wall time of last health_batch build
}
```

- [ ] **Step 3: Add `_refresh_health_batch()` (sync)**

Insert right after `_refresh_services_cache()` (after line ~399). This MOVES the
parse logic out of the handler so both the background loop and the cold-miss path
share it:

```python
def _refresh_health_batch():
    """Build the sidebar health snapshot in ONE systemctl list-units call.

    Stores _cache["health_batch"] = {modules, count} + stamps health_batch_ts.
    Shared by the background loop and the /public/health-batch cold-miss path so
    the request never makes its own (3.3 s) synchronous systemctl call.
    """
    modules = {}
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service",
             "--state=running,failed,inactive", "--no-legend", "--plain",
             "secubox-*"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                unit, _load, active, sub = parts[0], parts[1], parts[2], parts[3]
                if unit.startswith("secubox-") and unit.endswith(".service"):
                    mod_id = unit[8:-8]
                    if active == "active" and sub == "running":
                        modules[mod_id] = {"status": "ok", "msg": "Running"}
                    elif active == "active":
                        modules[mod_id] = {"status": "warn", "msg": f"Active ({sub})"}
                    elif active == "failed":
                        modules[mod_id] = {"status": "error", "msg": "Failed"}
                    else:
                        modules[mod_id] = {"status": "warn", "msg": f"{active}/{sub}"}
    except Exception as e:
        log.warning("health-batch systemctl error: %s", e)

    socket_dir = Path("/run/secubox")
    if socket_dir.exists():
        for sock in socket_dir.glob("*.sock"):
            mod_id = sock.stem
            if mod_id not in modules:
                modules[mod_id] = {"status": "ok", "msg": "Socket active"}

    _cache["health_batch"] = {"modules": modules, "count": len(modules)}
    _cache["health_batch_ts"] = time.time()
```

- [ ] **Step 4: Add `_ensure_services_warm()` (async)**

Insert right after `_svc()` (after line ~542):

```python
async def _ensure_services_warm():
    """Refresh the services cache in ONE batched call when cold/stale.

    Replaces the ~16 per-module `systemctl is-active` fallbacks inside _svc()
    with a single offloaded `is-active -- [all]` so dashboard/status/modules cold
    paths cost one call instead of sixteen, and never block the shared loop.
    """
    if (time.time() - _cache["last_refresh"]) >= CACHE_TTL * 2:
        await asyncio.to_thread(_refresh_services_cache)
        _cache["last_refresh"] = time.time()
```

- [ ] **Step 5: Run tests**

Run: `cd packages/secubox-hub && python -m pytest tests/test_cache_warm.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-hub/api/main.py packages/secubox-hub/tests/test_cache_warm.py
git commit -m "perf(hub): add _ensure_services_warm + _refresh_health_batch cache helpers (ref #644)"
```

---

### Task 2: Hub — wire helpers into handlers + background loop

**Files:**
- Modify: `packages/secubox-hub/api/main.py`
- Test: `packages/secubox-hub/tests/test_cache_warm.py` (extend)

- [ ] **Step 1: Add failing test for health-batch cache-serve**

Append to `tests/test_cache_warm.py`:

```python
def test_health_batch_serves_cache_without_subprocess(monkeypatch):
    _reset_cache()
    main._cache["health_batch"] = {"modules": {"hub": {"status": "ok", "msg": "Running"}}, "count": 1}
    main._cache["health_batch_ts"] = main.time.time()

    def boom(*a, **k):
        raise AssertionError("subprocess must NOT be called when cache is warm")

    monkeypatch.setattr(main.subprocess, "run", boom)
    out = asyncio.run(main.public_health_batch())
    assert out["count"] == 1
    assert out["modules"]["hub"]["status"] == "ok"


def test_health_batch_cold_miss_builds_once(monkeypatch):
    _reset_cache()

    class R:
        stdout = "secubox-hub.service loaded active running Hub\n"

    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        return R()

    monkeypatch.setattr(main.subprocess, "run", fake_run)
    out = asyncio.run(main.public_health_batch())
    assert out["count"] >= 1
    assert calls["n"] == 1
```

Run: `cd packages/secubox-hub && python -m pytest tests/test_cache_warm.py -v`
Expected: FAIL (handler still builds inline every call / no cache check).

- [ ] **Step 2: Rewrite `public_health_batch` to serve the snapshot**

Replace the body of `public_health_batch` (lines ~263-314) with:

```python
@public_router.get("/health-batch")
async def public_health_batch():
    """Batch health check for all modules — returns status for sidebar LEDs.

    Serves the TTL snapshot built by the background loop; on a cold miss it
    builds it ONCE off the event loop. Never makes a synchronous systemctl call
    on the request path.
    """
    hb = _cache.get("health_batch")
    if not hb or (time.time() - _cache.get("health_batch_ts", 0)) >= CACHE_TTL * 2:
        await asyncio.to_thread(_refresh_health_batch)
        hb = _cache.get("health_batch") or {"modules": {}, "count": 0}
    return hb
```

(The `import subprocess` inside the old handler is removed; `subprocess` is
already imported at module level.)

- [ ] **Step 3: Warm health-batch on `/dashboard`, `/status`, `/modules`**

In each of `status` (line ~545), `modules` (~554), and `dashboard` (~593), add
`await _ensure_services_warm()` immediately before the `_svc` loop. Example for
`dashboard`:

```python
@router.get("/dashboard")
async def dashboard(user=Depends(require_jwt)):
    """Données complètes du dashboard (uses cached stats for speed)."""
    board = get_board_info()
    await _ensure_services_warm()
    # _svc() now hits the warm cache (one batched refresh above on a cold cache).
    modules_status = await asyncio.to_thread(lambda: {k: _svc(v) for k, v in MODULES.items()})
```

Apply the same single `await _ensure_services_warm()` line before the `_svc`
comprehension in `status` and `modules` (keep the existing `await
asyncio.to_thread(...)` comprehension that follows).

- [ ] **Step 4: Build health-batch in the background loop**

In `_background_cache_refresh` (after the `_refresh_system_stats` line ~428) add:

```python
            await asyncio.to_thread(_refresh_health_batch)
```

And in `_start_background_once` initial warm (after line ~466
`_refresh_system_stats`) add the same line so the snapshot is warm before the
first sidebar poll:

```python
        await asyncio.to_thread(_refresh_health_batch)
```

- [ ] **Step 5: Run full hub test suite**

Run: `cd packages/secubox-hub && python -m pytest tests/ -v`
Expected: PASS (new + any existing).

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-hub/api/main.py packages/secubox-hub/tests/test_cache_warm.py
git commit -m "perf(hub): serve dashboard/health-batch from cache, one batched systemctl on cold path (ref #644)"
```

---

### Task 3: Toolbox — cap `/admin/clients/rich` enrichment to displayed rows

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py`
- Test: `packages/secubox-toolbox/tests/test_clients_rich_cap.py` (create)

- [ ] **Step 1: Write failing test**

Create `packages/secubox-toolbox/tests/test_clients_rich_cap.py`:

```python
import asyncio

from secubox_toolbox import api


def test_clients_rich_caps_enrichment(monkeypatch):
    rows = [
        {"mac_hash": f"m{i}", "ip": f"10.0.0.{i}", "state": "active",
         "level": "r1", "score": 0, "last_seen": float(i), "first_seen": 0.0}
        for i in range(20)
    ]
    monkeypatch.setattr(api.store, "list_clients", lambda: rows)
    monkeypatch.setattr(api.store, "latest_user_agent", lambda mh: "Mozilla/5.0")

    geo_calls = {"n": 0}

    def fake_lookup(ip):
        geo_calls["n"] += 1
        return {"flag": "🇫🇷", "country_iso": "FR", "asn_org": "X"}

    monkeypatch.setattr(api.geo, "lookup", fake_lookup)

    out = asyncio.run(api.admin_clients_rich())
    assert out["count"] == 20
    # Geo enrichment bounded to ENRICH_LIMIT, not all 20 clients.
    assert geo_calls["n"] == api.ENRICH_LIMIT
    # Most-recent client (last_seen highest) is enriched.
    assert out["clients"][0]["flag"] == "🇫🇷"
    # A client beyond the cap has bare geo fields.
    assert out["clients"][-1]["flag"] == ""
```

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_rich_cap.py -v`
Expected: FAIL (`ENRICH_LIMIT` undefined; all rows enriched).

- [ ] **Step 2: Add `ENRICH_LIMIT` + cap enrichment**

In `api.py`, add a module-level constant near the other config constants (top of
file, after imports):

```python
# Cap geo/UA enrichment on /admin/clients/rich to the rows the UI actually shows
# (top-5 + headroom). Beyond this, clients get bare fields — avoids ~51 cached
# geo lookups per poll (ref #644).
ENRICH_LIMIT = 12
```

Then rewrite the loop in `admin_clients_rich` (lines ~2917-2978) to sort by
`last_seen` desc and only enrich the first `ENRICH_LIMIT`:

```python
    rows = store.list_clients()
    rows = sorted(rows, key=lambda r: (r.get("last_seen") or 0), reverse=True)
    now = _t.time()
    enriched = []
    for idx, r in enumerate(rows):
        age_min = (now - (r.get("last_seen") or 0)) / 60.0
        if age_min < 5:
            status_emoji = "🟢"
            status_label = "actif"
        elif age_min < 60:
            status_emoji = "🟡"
            status_label = "idle"
        else:
            status_emoji = "⚪"
            status_label = "expiré"
        if r.get("state") == "quarantine":
            status_emoji = "🔴"
            status_label = "quarantine"
        level = r.get("level") or "r1"
        level_emoji = {"r0": "🌐", "r1": "🛡", "r2": "🔍", "r3": "🌐"}.get(level, "❔")
        score = r.get("score", 0)
        risk_emoji = "🟢" if score < 30 else "🟡" if score < 70 else "🔴"

        # Device + geo enrichment only for the displayed rows (ENRICH_LIMIT).
        dev_emoji, dev_label = "📱", ""
        flag = country_iso = asn_org = ""
        if idx < ENRICH_LIMIT:
            try:
                ua = store.latest_user_agent(r.get("mac_hash") or "")
                if ua:
                    cl = _av.classify_user_agent(ua)
                    dev_emoji = cl.get("device_emoji") or dev_emoji
                    dev_label = cl.get("device") or ""
            except Exception:
                pass
            try:
                gi = _geo.lookup(r.get("ip") or "")
                flag = gi.get("flag", "") or ""
                country_iso = gi.get("country_iso", "") or ""
                asn_org = gi.get("asn_org", "") or ""
            except Exception:
                pass

        enriched.append({
            "mac_hash": r.get("mac_hash"),
            "ip": r.get("ip"),
            "state": r.get("state"),
            "level": level,
            "level_emoji": level_emoji,
            "score": score,
            "risk_emoji": risk_emoji,
            "status_emoji": status_emoji,
            "status_label": status_label,
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "device_emoji": dev_emoji,
            "device": dev_label,
            "flag": flag,
            "country_iso": country_iso,
            "asn_org": asn_org,
        })
    return {"clients": enriched, "count": len(enriched)}
```

- [ ] **Step 3: Run tests**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_rich_cap.py -v`
Expected: PASS.

- [ ] **Step 4: Run full toolbox suite (no regressions)**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q`
Expected: PASS (existing clients/rich test, if any, still green).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_clients_rich_cap.py
git commit -m "perf(toolbox): cap /admin/clients/rich enrichment to ENRICH_LIMIT most-recent rows (ref #644)"
```

---

### Task 4: Changelogs + version bumps

**Files:**
- Modify: `packages/secubox-hub/debian/changelog`
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Bump hub changelog**

Add a new top entry (use the next patch version after the current one; check the
current top with `head -1 packages/secubox-hub/debian/changelog`). Body:
`perf: dashboard/status/modules + health-batch served from TTL cache; one batched
systemctl on cold path (9-12 s → <100 ms) (ref #644)`.

- [ ] **Step 2: Bump toolbox changelog**

Add a new top entry after the current top (2.6.51). Body:
`perf: /admin/clients/rich enriches only the ENRICH_LIMIT most-recent rows (ref #644)`.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-hub/debian/changelog packages/secubox-toolbox/debian/changelog
git commit -m "chore: changelogs for hub latency + toolbox clients/rich cap (ref #644)"
```

---

## Self-Review notes
- Spec coverage: Task1=helpers(#1,#2), Task2=wiring(#3,#4,#5), Task3=clients cap(#6). All spec items mapped.
- `_ensure_services_warm` uses `CACHE_TTL*2` staleness window — identical to `_svc`'s own freshness gate, so a warm cache short-circuits and a stale one triggers exactly one batched refresh.
- health-batch returns the raw snapshot dict (same shape as before: `{modules,count}`), so `sidebar.js` is unaffected.
- clients/rich sorts by `last_seen` desc so the enriched rows are the ones the UI surfaces (top-5 + headroom to 12).
