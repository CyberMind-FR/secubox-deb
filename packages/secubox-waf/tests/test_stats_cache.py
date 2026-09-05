# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for StatsCache + endpoint cache wiring in secubox-waf.

Pattern reference: CLAUDE.md § Performance Patterns — Double Caching.

Verifies:
- StatsCache.get/set roundtrip
- TTL expiry returns None
- invalidate(key) clears one key, invalidate() clears all
- /stats and /alerts wire through the cache (hit on second call,
  underlying loader called exactly once within TTL)
- /alerts cache is keyed on (limit, aggregate) so different views
  don't collide
- Mutating endpoints (ban/unban/reload) invalidate the cache
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Make the package importable without an install step
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Stub out secubox_core before importing waf.api — production deps
# (auth, config) aren't needed for these unit tests.
from types import ModuleType

if "secubox_core" not in sys.modules:
    secubox_core = ModuleType("secubox_core")
    auth_mod = ModuleType("secubox_core.auth")
    auth_mod.require_jwt = lambda: None
    config_mod = ModuleType("secubox_core.config")
    config_mod.get_config = lambda *_a, **_k: {}
    secubox_core.auth = auth_mod
    secubox_core.config = config_mod
    sys.modules["secubox_core"] = secubox_core
    sys.modules["secubox_core.auth"] = auth_mod
    sys.modules["secubox_core.config"] = config_mod

# geoip2 may or may not be installed in CI; stub it out.
if "geoip2" not in sys.modules:
    geoip2 = ModuleType("geoip2")
    geoip2_db = ModuleType("geoip2.database")
    geoip2_db.Reader = object
    geoip2_err = ModuleType("geoip2.errors")
    class _AddressNotFoundError(Exception): ...
    geoip2_err.AddressNotFoundError = _AddressNotFoundError
    sys.modules["geoip2"] = geoip2
    sys.modules["geoip2.database"] = geoip2_db
    sys.modules["geoip2.errors"] = geoip2_err

from api import main as waf_main  # noqa: E402
from api.main import StatsCache  # noqa: E402


# ──────────────────────────────────────────────────────────────────────
# StatsCache unit tests
# ──────────────────────────────────────────────────────────────────────

def test_get_miss_returns_none():
    c = StatsCache(ttl_seconds=10)
    assert c.get("absent") is None


def test_set_then_get_returns_value():
    c = StatsCache(ttl_seconds=10)
    c.set("k", {"a": 1})
    assert c.get("k") == {"a": 1}


def test_get_after_ttl_expires_returns_none():
    c = StatsCache(ttl_seconds=10)
    c.set("k", "v")
    # Fake elapsed time without sleep
    c._timestamps["k"] = time.time() - 11
    assert c.get("k") is None
    # And the entry is evicted on miss
    assert "k" not in c._cache


def test_invalidate_single_key():
    c = StatsCache(ttl_seconds=10)
    c.set("a", 1)
    c.set("b", 2)
    c.invalidate("a")
    assert c.get("a") is None
    assert c.get("b") == 2


def test_invalidate_all():
    c = StatsCache(ttl_seconds=10)
    c.set("a", 1)
    c.set("b", 2)
    c.invalidate()
    assert c.get("a") is None
    assert c.get("b") is None


def test_set_overwrites_and_refreshes_ttl():
    c = StatsCache(ttl_seconds=10)
    c.set("k", "v1")
    c._timestamps["k"] = time.time() - 9  # still fresh
    c.set("k", "v2")
    # Should still be fresh and updated
    assert c.get("k") == "v2"


# ──────────────────────────────────────────────────────────────────────
# Endpoint integration: cache hit avoids second loader call
# ──────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_module_cache():
    """Each test starts with an empty module-level cache."""
    waf_main.stats_cache.invalidate()
    yield
    waf_main.stats_cache.invalidate()


def _run(coro):
    """Tiny sync runner so we don't need pytest-asyncio for one call."""
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


def test_get_stats_caches_underlying_loader():
    """Second call within TTL must not re-invoke _get_threat_stats."""
    fake = {"total_threats": 42, "by_category": {}, "by_severity": {},
            "top_ips": {}, "top_countries": {}, "top_vhosts": {},
            "top_ips_countries": {}, "threats_today": 0}
    with patch.object(waf_main, "_get_threat_stats", return_value=fake) as loader, \
         patch.object(waf_main, "_cfg", return_value={"enabled": True}), \
         patch.object(waf_main, "_compiled_patterns", {}):
        r1 = _run(waf_main.get_stats())
        r2 = _run(waf_main.get_stats())
    assert loader.call_count == 1, "loader called more than once → cache bypassed"
    assert r1 == r2
    assert r1["total_threats"] == 42


def test_get_stats_recomputes_after_ttl():
    fake1 = {"total_threats": 1, "by_category": {}, "by_severity": {},
             "top_ips": {}, "top_countries": {}, "top_vhosts": {},
             "top_ips_countries": {}, "threats_today": 0}
    fake2 = dict(fake1, total_threats=2)
    with patch.object(waf_main, "_get_threat_stats", side_effect=[fake1, fake2]) as loader, \
         patch.object(waf_main, "_cfg", return_value={"enabled": True}), \
         patch.object(waf_main, "_compiled_patterns", {}):
        r1 = _run(waf_main.get_stats())
        # Force TTL expiry without real sleep
        waf_main.stats_cache._timestamps["threat_stats"] = time.time() - 31
        r2 = _run(waf_main.get_stats())
    assert loader.call_count == 2
    assert r1["total_threats"] == 1
    assert r2["total_threats"] == 2


def test_get_alerts_cache_keyed_per_view(tmp_path):
    """Different (limit, aggregate) params must not collide in the cache."""
    log = tmp_path / "waf-threats.log"
    log.write_text('{"client_ip":"1.2.3.4","category":"xss","severity":"high","timestamp":"2026-05-15T15:00:00"}\n')
    with patch.object(waf_main, "THREATS_LOG", str(log)):
        r1 = _run(waf_main.get_alerts(limit=10, aggregate=False))
        r2 = _run(waf_main.get_alerts(limit=10, aggregate=True))
        r3 = _run(waf_main.get_alerts(limit=10, aggregate=False))  # hit
    assert r1["aggregated"] is False
    assert r2["aggregated"] is True
    assert r1 == r3, "same (limit, aggregate) tuple must hit cache"
    # All three keys recorded
    assert "alerts:10:0" in waf_main.stats_cache._cache
    assert "alerts:10:1" in waf_main.stats_cache._cache


def test_get_alerts_missing_log_caches_empty():
    """Even the empty-log fast path is cached so the .exists() check doesn't repeat."""
    with patch.object(waf_main, "THREATS_LOG", "/nonexistent/path/to/log"):
        r1 = _run(waf_main.get_alerts(limit=50, aggregate=False))
        # Mutate the cache directly to detect re-execution
        waf_main.stats_cache._cache["alerts:50:0"] = {"sentinel": True}
        r2 = _run(waf_main.get_alerts(limit=50, aggregate=False))
    assert r1 == {"alerts": []}
    assert r2 == {"sentinel": True}, "second call bypassed cache"


def test_ban_invalidates_cache():
    """Manually banning an IP must clear cached stats/alerts."""
    waf_main.stats_cache.set("threat_stats", {"stale": True})
    waf_main.stats_cache.set("alerts:50:0", {"stale": True})
    with patch.object(waf_main, "_ban_ip"):
        req = waf_main.BanRequest(ip="1.2.3.4", duration="4h", reason="test")
        _run(waf_main.ban_ip(req))
    assert waf_main.stats_cache.get("threat_stats") is None
    assert waf_main.stats_cache.get("alerts:50:0") is None


def test_unban_invalidates_cache():
    waf_main.stats_cache.set("threat_stats", {"stale": True})
    with patch.object(waf_main, "_unban_ip"):
        _run(waf_main.unban_ip("1.2.3.4"))
    assert waf_main.stats_cache.get("threat_stats") is None


def test_reload_invalidates_cache():
    waf_main.stats_cache.set("threat_stats", {"stale": True})
    with patch.object(waf_main, "_load_rules"), \
         patch.object(waf_main, "_compiled_patterns", {}):
        _run(waf_main.reload_rules())
    assert waf_main.stats_cache.get("threat_stats") is None
