# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Fail-safe coverage for `_frigate_get` itself (no mock of the function),
plus the /events truncation contract (#821 review fix)."""
import importlib
import socket
import urllib.error
import urllib.request

from fastapi.testclient import TestClient


def _reload():
    import api.main as m
    importlib.reload(m)
    return m


def test_frigate_get_network_error_is_failsafe(monkeypatch):
    m = _reload()

    def raise_urlerror(*a, **kw):
        raise urllib.error.URLError("timeout")

    monkeypatch.setattr(urllib.request, "urlopen", raise_urlerror)
    assert m._frigate_get("/api/stats") == (None, False)


def test_frigate_get_socket_timeout_is_failsafe(monkeypatch):
    m = _reload()

    def raise_timeout(*a, **kw):
        raise socket.timeout("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", raise_timeout)
    assert m._frigate_get("/api/stats") == (None, False)


def test_frigate_get_non_2xx_is_failsafe(monkeypatch):
    m = _reload()

    def raise_http_error(*a, **kw):
        raise urllib.error.HTTPError(
            "http://frigate/api/stats", 503, "Service Unavailable", hdrs=None, fp=None
        )

    monkeypatch.setattr(urllib.request, "urlopen", raise_http_error)
    assert m._frigate_get("/api/stats") == (None, False)


def test_frigate_get_invalid_json_is_failsafe(monkeypatch):
    m = _reload()

    class FakeResponse:
        def read(self):
            return b"not-json{{{"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResponse())
    assert m._frigate_get("/api/stats") == (None, False)


def test_events_truncated_to_limit(monkeypatch):
    m = _reload()
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "test"}

    many_events = [
        {"id": str(i), "label": "person", "camera": "demo", "start_time": i, "zones": []}
        for i in range(m.EVENTS_LIMIT + 25)
    ]

    def fake_get(path):
        if path.startswith("/api/events"):
            return many_events, True
        return {}, True

    monkeypatch.setattr(m, "_frigate_get", fake_get)
    c = TestClient(m.app)
    r = c.get("/api/v1/frigate/events")
    assert r.status_code == 200
    assert len(r.json()["events"]) == m.EVENTS_LIMIT
