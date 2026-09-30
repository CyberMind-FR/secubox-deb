# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for GET /apps/audit — the route consumed by the Mosaic tab (#956).

The endpoint used to shell out to `streamlitctl app audit` on every request
(~11s locally, ~31s through the aggregator — unusable for a dashboard tab).
It now serves a pre-computed cache written out-of-band by
streamlit-audit.timer (double-cache pattern, same as the PeerTube
transcoding backlog). These tests lock down the file-read contract: cache
absent, cache unreadable/corrupt, and a valid cache with age computed —
and that a cache miss never falls back to invoking the ctl (that fallback
would silently reintroduce the 31s the cache exists to remove).
"""
import json
import os
import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.main import app


def test_apps_audit_reports_unavailable_when_cache_missing(tmp_path):
    missing = tmp_path / "audit.json"
    with patch("api.main.APPS_AUDIT_CACHE", missing), \
         patch("api.main.subprocess.run") as run_mock:
        client = TestClient(app)
        r = client.get("/apps/audit")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is False
    assert body["reason"] == "cache not written yet"
    assert body["apps"] == []
    # A cache miss must never fall back to the (slow) ctl invocation.
    run_mock.assert_not_called()


def test_apps_audit_reports_unavailable_when_cache_is_corrupt(tmp_path):
    corrupt = tmp_path / "audit.json"
    corrupt.write_text("{not valid json")
    with patch("api.main.APPS_AUDIT_CACHE", corrupt), \
         patch("api.main.subprocess.run") as run_mock:
        client = TestClient(app)
        r = client.get("/apps/audit")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is False
    assert body["reason"] == "cache unreadable"
    run_mock.assert_not_called()


def test_apps_audit_reports_unavailable_when_cache_is_not_an_object(tmp_path):
    """The cache file must contain a JSON object; a bare list or scalar is
    treated the same as corruption rather than raising."""
    not_an_object = tmp_path / "audit.json"
    not_an_object.write_text("[1, 2, 3]")
    with patch("api.main.APPS_AUDIT_CACHE", not_an_object):
        client = TestClient(app)
        r = client.get("/apps/audit")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is False
    assert body["reason"] == "cache unreadable"


def test_apps_audit_serves_cached_payload_with_age(tmp_path):
    cache = tmp_path / "audit.json"
    payload = {
        "apps": [{"name": "fabricator", "shape": "dir", "entrypoint": "app.py",
                   "declared": True, "running": True, "port": 8520,
                   "issues": ["stale-port"]}],
        "summary": {"total": 66, "running": 15},
    }
    cache.write_text(json.dumps(payload))
    # Backdate mtime so cache_age_seconds is deterministically non-zero.
    old = time.time() - 120
    os.utime(cache, (old, old))

    with patch("api.main.APPS_AUDIT_CACHE", cache):
        client = TestClient(app)
        r = client.get("/apps/audit")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is True
    assert body["apps"][0]["name"] == "fabricator"
    assert body["summary"] == {"total": 66, "running": 15}
    assert body["cache_age_seconds"] >= 100


def test_apps_audit_needs_no_token_from_a_lan_dashboard(tmp_path):
    """No Authorization header: served, because the test harness is a LAN
    dashboard client (secubox_core.testing) — never because the route is
    public (see the refusal test just below)."""
    cache = tmp_path / "audit.json"
    cache.write_text(json.dumps({"apps": [], "summary": {}}))
    with patch("api.main.APPS_AUDIT_CACHE", cache):
        client = TestClient(app)
        r = client.get("/apps/audit")
    assert r.status_code == 200, r.text


def test_apps_audit_refused_to_an_anonymous_reader_outside_the_lan(tmp_path, monkeypatch):
    """Restored under the #1256 read guard (#1776): the fleet inventory is
    reconnaissance material — names, ports, paths — never served to an
    anonymous WAN reader."""
    from secubox_core.auth import ENTETE_LAN

    cache = tmp_path / "audit.json"
    cache.write_text(json.dumps({"apps": [], "summary": {}}))
    with patch("api.main.APPS_AUDIT_CACHE", cache):
        assert TestClient(app, headers={ENTETE_LAN: "0"}).get("/apps/audit").status_code == 401
        monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
        assert TestClient(app).get("/apps/audit").status_code == 401
