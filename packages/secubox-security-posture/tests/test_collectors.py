# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — collector normalization tests
CyberMind — https://cybermind.fr

Collectors are exercised with faked socket responses (no board needed) to prove
two things: real values normalize correctly, and an unreachable source yields an
UNKNOWN indicator (value None) rather than raising.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from posture import collectors, sources  # noqa: E402
from posture.model import Status  # noqa: E402


def _fake_sockets(mapping):
    """Return an async socket_get that serves canned (name, path) -> dict."""
    async def fake(name, path, timeout=3.0):
        data = mapping.get((name, path))
        return (True, data) if data is not None else (False, None)
    return fake


def _ind(indicators, ind_id):
    return next(i for i in indicators if i.id == ind_id)


def test_root_cpu_headroom_normalizes(monkeypatch):
    monkeypatch.setattr(sources, "socket_get", _fake_sockets({
        ("system", "/metrics"): {"cpu_percent": 20.0, "mem_percent": 40.0,
                                 "disk_percent": 10.0, "load_avg_1": 0.5},
        ("system", "/services"): {"services": [{"active": True}, {"active": True},
                                               {"active": False}]},
    }))
    inds = asyncio.run(collectors.collect_root(collectors.Probe()))
    assert _ind(inds, "cpu_headroom").value == 0.8        # 1 - 20/100
    assert _ind(inds, "cpu_headroom").status is Status.OK
    assert round(_ind(inds, "service_health").value, 3) == round(2 / 3, 3)


def test_root_unknown_when_system_down(monkeypatch):
    # Everything fails, and /proc fallbacks also unavailable on CI → UNKNOWN.
    monkeypatch.setattr(sources, "socket_get", _fake_sockets({}))
    monkeypatch.setattr(sources, "read_loadavg", lambda: None)
    monkeypatch.setattr(sources, "read_mem_available_ratio", lambda: None)
    inds = asyncio.run(collectors.collect_root(collectors.Probe()))
    sh = _ind(inds, "service_health")
    assert sh.status is Status.UNKNOWN
    assert sh.value is None
    assert sh.provenance.ok is False


def test_wall_waf_running(monkeypatch):
    monkeypatch.setattr(sources, "socket_get", _fake_sockets({
        ("waf", "/stats"): {"running": True, "rules_loaded": 1200},
    }))
    inds = asyncio.run(collectors.collect_wall(collectors.Probe()))
    assert _ind(inds, "waf_running").value == 1.0
    assert _ind(inds, "waf_running").status is Status.OK


def test_collect_all_returns_indicators(monkeypatch):
    monkeypatch.setattr(sources, "socket_get", _fake_sockets({}))
    inds = asyncio.run(collectors.collect_all())
    # Even with all sources down, collectors emit UNKNOWN indicators (never crash).
    assert len(inds) > 0
    assert all(i.value is None or 0.0 <= i.value <= 1.0 for i in inds)
