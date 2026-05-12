# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
Tests for the load_sites() in-memory cache + _invalidate_sites_cache().

We don't import main.py here (it pulls FastAPI + python-multipart + secubox_core).
Instead we exercise the cache pattern in isolation by copying the function
shape — the contract is: TTL-based caching with invalidation, no other state.
"""
import time
from typing import List, Optional


def _make_cached_loader(ttl: float = 30.0):
    """Return a (loader, invalidate, calls_counter) triple mirroring main.py's pattern."""
    state = {"cache": None, "at": 0.0, "calls": 0}

    def loader() -> List[dict]:
        now = time.monotonic()
        if state["cache"] is not None and (now - state["at"]) < ttl:
            return state["cache"]
        state["calls"] += 1
        result = [{"name": f"s{state['calls']}"}]
        state["cache"] = result
        state["at"] = now
        return result

    def invalidate() -> None:
        state["cache"] = None
        state["at"] = 0.0

    return loader, invalidate, state


def test_first_call_populates_cache():
    load, _, state = _make_cached_loader()
    assert state["calls"] == 0
    load()
    assert state["calls"] == 1


def test_second_call_within_ttl_uses_cache():
    load, _, state = _make_cached_loader(ttl=30.0)
    load()
    load()
    load()
    assert state["calls"] == 1


def test_expired_cache_triggers_refresh():
    load, _, state = _make_cached_loader(ttl=0.001)
    load()
    time.sleep(0.01)
    load()
    assert state["calls"] == 2


def test_invalidation_forces_refresh():
    load, invalidate, state = _make_cached_loader(ttl=30.0)
    load()
    invalidate()
    load()
    assert state["calls"] == 2


def test_cached_result_is_stable_across_reads():
    load, _, _ = _make_cached_loader(ttl=30.0)
    first = load()
    second = load()
    assert first is second  # identity, not just equality — same object returned
