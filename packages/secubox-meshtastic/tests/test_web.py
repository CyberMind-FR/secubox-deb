# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Tests API web (packages/secubox-meshtastic/api/web.py).

`common/` est ajouté à sys.path pour importer le VRAI secubox_core.auth
(comme packages/secubox-profiles/tests/test_web.py) : un test vérifie que
require_jwt réel est bien branché (401 sans credentials) avant que les
autres tests ne le bypassent via dependency_overrides.

`cache`/`send_cb`/`ctl_cb` sont de simples fakes injectés via
`web.create_app(...)` — aucun accès réel au radio/ctl n'est nécessaire ici,
seule la surface HTTP (routes, validation avant délégation, JWT) est
couverte.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "common"))
# packages/secubox-meshtastic itself is already on sys.path via conftest.py.

from fastapi.testclient import TestClient  # noqa: E402

import api.web as web  # noqa: E402


def _noop_jwt():
    return {"sub": "admin"}


class FakeCache:
    def __init__(self, state: dict) -> None:
        self.state = state

    def get(self) -> dict:
        return self.state


STATE = {
    "radio": "present",
    "mode": "active-node",
    "nodes": [{"id": "!abcd1234", "name": "node-1"}],
    "messages_by_channel": {"0": [{"from": "!abcd1234", "text": "hi"}]},
    "census": [{"id": "!deadbeef", "rssi": -80}],
    "channel_stats": {"0": {"count": 5}},
}


@pytest.fixture()
def send_calls():
    return []


@pytest.fixture()
def ctl_calls():
    return []


@pytest.fixture()
def client(send_calls, ctl_calls):
    def send_cb(channel, text):
        send_calls.append((channel, text))
        return {"status": "sent", "channel": channel, "text": text}

    def ctl_cb(verb, **kwargs):
        ctl_calls.append((verb, kwargs))
        return {"status": "applied", "verb": verb, **kwargs}

    cache = FakeCache(dict(STATE))
    app = web.create_app(cache, send_cb, ctl_cb)
    c = TestClient(app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    yield c
    c.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# JWT gating
# ---------------------------------------------------------------------------

def test_status_requires_jwt_when_not_overridden():
    # Real secubox_core.auth.require_jwt (no override): no Authorization
    # header, no session cookie -> 401. Confirms Depends(require_jwt) is
    # actually wired on the route, not just imported.
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {})
    c = TestClient(app)
    resp = c.get("/api/v1/meshtastic/status")
    assert resp.status_code == 401


def test_all_routes_require_jwt_when_not_overridden():
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {})
    c = TestClient(app)
    assert c.get("/api/v1/meshtastic/nodes").status_code == 401
    assert c.get("/api/v1/meshtastic/messages").status_code == 401
    assert c.get("/api/v1/meshtastic/packets").status_code == 401
    assert c.post("/api/v1/meshtastic/send", json={"channel": 0, "text": "x"}).status_code == 401
    assert c.post("/api/v1/meshtastic/mode", json={"mode": "both"}).status_code == 401
    assert c.post("/api/v1/meshtastic/grid",
                   json={"channel": "LongFast", "grid": ["shared"]}).status_code == 401


# ---------------------------------------------------------------------------
# read paths
# ---------------------------------------------------------------------------

def test_status_returns_cache_dict(client):
    resp = client.get("/api/v1/meshtastic/status")
    assert resp.status_code == 200
    assert resp.json() == STATE


def test_nodes_returns_cache_nodes(client):
    resp = client.get("/api/v1/meshtastic/nodes")
    assert resp.status_code == 200
    assert resp.json() == STATE["nodes"]


def test_messages_returns_cache_messages(client):
    resp = client.get("/api/v1/meshtastic/messages")
    assert resp.status_code == 200
    assert resp.json() == STATE["messages_by_channel"]


def test_packets_returns_census_and_channel_stats(client):
    resp = client.get("/api/v1/meshtastic/packets")
    assert resp.status_code == 200
    assert resp.json() == {
        "census": STATE["census"],
        "channel_stats": STATE["channel_stats"],
    }


def test_read_routes_tolerate_missing_keys():
    # cache.get() may return a bare-bones dict (e.g. right after boot) — the
    # read routes must not KeyError, they default to [] / {}.
    app = web.create_app(FakeCache({}), lambda c, t: {}, lambda v, **kw: {})
    c = TestClient(app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    assert c.get("/api/v1/meshtastic/nodes").json() == []
    assert c.get("/api/v1/meshtastic/messages").json() == {}
    assert c.get("/api/v1/meshtastic/packets").json() == {"census": [], "channel_stats": {}}


# ---------------------------------------------------------------------------
# POST /send
# ---------------------------------------------------------------------------

def test_send_calls_send_cb_with_channel_and_text(client, send_calls):
    resp = client.post("/api/v1/meshtastic/send", json={"channel": 2, "text": "hello mesh"})
    assert resp.status_code == 200
    assert send_calls == [(2, "hello mesh")]
    assert resp.json() == {"status": "sent", "channel": 2, "text": "hello mesh"}


# ---------------------------------------------------------------------------
# POST /mode — validate BEFORE delegating (mirror profiles set_pin/set_lifecycle)
# ---------------------------------------------------------------------------

def test_mode_bad_value_422_and_ctl_not_called(client, ctl_calls):
    resp = client.post("/api/v1/meshtastic/mode", json={"mode": "bogus-mode"})
    assert resp.status_code == 422
    assert ctl_calls == []


def test_mode_good_value_delegates_to_ctl(client, ctl_calls):
    resp = client.post("/api/v1/meshtastic/mode", json={"mode": "passive-listener"})
    assert resp.status_code == 200
    assert ctl_calls == [("set-mode", {"mode": "passive-listener"})]
    assert resp.json()["status"] == "applied"


# ---------------------------------------------------------------------------
# POST /grid — validate every grid value BEFORE delegating
# ---------------------------------------------------------------------------

def test_grid_bad_value_422_and_ctl_not_called(client, ctl_calls):
    resp = client.post("/api/v1/meshtastic/grid",
                        json={"channel": "LongFast", "grid": ["shared", "bogus"]})
    assert resp.status_code == 422
    assert ctl_calls == []


def test_grid_good_value_delegates_to_ctl(client, ctl_calls):
    resp = client.post("/api/v1/meshtastic/grid",
                        json={"channel": "LongFast", "grid": ["off", "shared"]})
    assert resp.status_code == 200
    assert ctl_calls == [("set-grid", {"channel": "LongFast", "grid": ["off", "shared"]})]


# ---------------------------------------------------------------------------
# GET /channel-url — sharable join link (discloses the channel key)
# ---------------------------------------------------------------------------

def test_channel_url_requires_jwt_when_not_overridden():
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {},
                         lambda: {"url": "x"})
    c = TestClient(app)
    assert c.get("/api/v1/meshtastic/channel-url").status_code == 401


def test_channel_url_returns_url_from_cb():
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {},
                         lambda: {"url": "https://meshtastic.org/e/#ABC"})
    c = TestClient(app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    resp = c.get("/api/v1/meshtastic/channel-url")
    assert resp.status_code == 200
    assert resp.json() == {"url": "https://meshtastic.org/e/#ABC"}
    c.app.dependency_overrides.clear()


def test_channel_url_503_when_no_cb():
    # No channel_url_cb wired (radio absent at wiring time) -> 503, not 500.
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {})
    c = TestClient(app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    assert c.get("/api/v1/meshtastic/channel-url").status_code == 503
    c.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /device-config — live device configuration
# ---------------------------------------------------------------------------

def test_device_config_requires_jwt_when_not_overridden():
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {},
                         None, lambda: {"firmware": "x"})
    c = TestClient(app)
    assert c.get("/api/v1/meshtastic/device-config").status_code == 401


def test_device_config_returns_cb():
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {},
                         None, lambda: {"firmware": "2.7.15", "region": "EU_868", "ble_enabled": True})
    c = TestClient(app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    resp = c.get("/api/v1/meshtastic/device-config")
    assert resp.status_code == 200
    assert resp.json()["region"] == "EU_868"
    c.app.dependency_overrides.clear()


def test_device_config_503_when_no_cb():
    app = web.create_app(FakeCache(dict(STATE)), lambda c, t: {}, lambda v, **kw: {})
    c = TestClient(app)
    c.app.dependency_overrides[web.require_jwt] = _noop_jwt
    assert c.get("/api/v1/meshtastic/device-config").status_code == 503
    c.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# no direct radio/systemctl/subprocess access from web.py
# ---------------------------------------------------------------------------

def test_web_module_has_no_actuation_helper():
    # Grep over actual code lines only (skip comments/docstring prose, which
    # legitimately discuss what the PRODUCTION send_cb/ctl_cb wire up to) —
    # web.py itself must never import subprocess or shell out directly.
    src = Path(web.__file__).read_text(encoding="utf-8")
    code_lines = [ln for ln in src.splitlines() if not ln.strip().startswith("#")]
    code = "\n".join(code_lines)
    for forbidden in ("import subprocess", "os.system", "Popen("):
        assert forbidden not in code
