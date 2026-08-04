# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""GET /sites + POST /sites/refresh — cache-backed, never recomputed (#974).

Before this fix, GET /sites called load_sites(), which forks `git` x2 and
`du` once per site synchronously inside the async handler — measured at
~14.6s for 172 sites on the board, and observed hanging past 90s under
concurrent load because every request fully serializes on the module's
single uvicorn worker. These tests lock down the fix's contract: the
handler is a pure cache read (subprocess is never invoked), a missing/
corrupt cache is reported distinctly from a genuinely empty fleet, and a
manual refresh is a fire-and-forget trigger, not an inline recompute.

Run from packages/secubox-metablogizer/ with secubox_core importable:
    PYTHONPATH=api:../../common ../../.venv/bin/pytest api/tests/test_sites_route.py -v
"""
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import importlib
    import main as m
    importlib.reload(m)

    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}

    cache = tmp_path / "sites.json"
    monkeypatch.setattr(m, "SITES_CACHE_PATH", cache)

    yield TestClient(m.app), cache, m
    m.app.dependency_overrides.clear()


def _write_cache(path, sites):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sites": sites, "count": len(sites),
                                 "generated_at": "2026-08-04T00:00:00+0200"}))


# ─────────────────────────────────────────────────────────────────────────
# GET /sites serves the cache, never recomputes
# ─────────────────────────────────────────────────────────────────────────

def test_sites_serves_cached_payload(client):
    c, cache, _m = client
    _write_cache(cache, [{"name": "alpha", "domain": "alpha.gk2.secubox.in"}])

    resp = c.get("/sites")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["sites"][0]["name"] == "alpha"
    assert body["available"] is True


def test_sites_never_shells_out(client):
    """The bug this fixes: load_sites() forked git+du per site inside the
    request handler. A cache-backed handler must never touch subprocess at
    all, cache hit or miss."""
    c, cache, m = client
    _write_cache(cache, [{"name": "alpha"}])

    with patch.object(m.subprocess, "run") as run_mock:
        resp = c.get("/sites")

    assert resp.status_code == 200
    run_mock.assert_not_called()


def test_sites_missing_cache_never_falls_back_to_live_scan(client):
    """A cache miss must be reported, not silently recomputed — recomputing
    here would reintroduce the exact hang this fix removes."""
    c, cache, m = client
    assert not cache.exists()

    with patch.object(m.subprocess, "run") as run_mock:
        resp = c.get("/sites")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["available"] is False
    assert body["reason"] == "cache not written yet"
    run_mock.assert_not_called()


def test_sites_missing_cache_is_not_confused_with_empty_fleet(client):
    """A missing cache and a genuinely empty fleet must be
    distinguishable — an empty `sites: []` must never be the only signal."""
    c, cache, _m = client

    missing_resp = c.get("/sites").json()

    _write_cache(cache, [])
    empty_resp = c.get("/sites").json()

    assert missing_resp["sites"] == [] == empty_resp["sites"]
    assert missing_resp["available"] is False
    assert empty_resp["available"] is True
    assert missing_resp != empty_resp


def test_sites_corrupt_cache_reported_not_500(client):
    c, cache, _m = client
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("{not valid json")

    resp = c.get("/sites")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["available"] is False
    assert body["reason"] == "cache unreadable"


def test_sites_reports_cache_age(client):
    c, cache, _m = client
    _write_cache(cache, [{"name": "a"}])

    resp = c.get("/sites")

    assert resp.json()["cache_age_seconds"] is not None


def test_sites_requires_jwt(monkeypatch):
    """Unlike the public screenshot/audit endpoints, /sites stays behind
    JWT — only the compute strategy changed, not the auth contract."""
    import importlib
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import main as m
    importlib.reload(m)
    c = TestClient(m.app)
    resp = c.get("/sites")
    assert resp.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────
# POST /sites/refresh — fire-and-forget trigger, never an inline recompute
# ─────────────────────────────────────────────────────────────────────────

def test_refresh_triggers_systemctl_without_blocking(client):
    c, _cache, m = client
    with patch.object(m.subprocess, "Popen") as popen_mock, \
         patch.object(m, "sites_scan") as scan_mock:
        resp = c.post("/sites/refresh")

    assert resp.status_code == 200, resp.text
    assert resp.json()["triggered"] is True
    popen_mock.assert_called_once()
    args = popen_mock.call_args[0][0]
    assert "systemctl" in args[-4] or "systemctl" in args
    assert "--no-block" in args
    assert "start" in args
    assert any("metablog-audit" in a for a in args)
    # The refresh trigger must NEVER call the scan itself — that would be
    # exactly the blocking recompute this endpoint exists to avoid.
    scan_mock.scan_sites.assert_not_called()
    scan_mock.main.assert_not_called()


def test_refresh_survives_missing_systemctl(client):
    """sudo/systemctl absent in a test/dev sandbox must not 500 the
    endpoint — the trigger is best-effort."""
    c, _cache, m = client
    with patch.object(m.subprocess, "Popen", side_effect=FileNotFoundError):
        resp = c.post("/sites/refresh")
    assert resp.status_code == 200, resp.text
    assert resp.json()["triggered"] is False
