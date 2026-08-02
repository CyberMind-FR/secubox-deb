# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""GET /site/{name}/screenshot — public read of the conserved thumbnail (#956).

Run from packages/secubox-metablogizer/ with secubox_core importable:
    PYTHONPATH=api:../../common ../../.venv/bin/pytest api/tests/test_site_screenshot_route.py -v
"""
import pytest
from fastapi.testclient import TestClient

from secubox_core import screenshots


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    # Same guard as test_publish_router.py: prevent get_config() (called at
    # main.py import time) from touching a real /etc/secubox/secubox.conf
    # that may exist (and not be readable) on the machine running the tests.
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import importlib
    import main as m
    importlib.reload(m)
    cache = tmp_path / "shots"
    monkeypatch.setattr(m, "SHOTS_CACHE_DIR", cache)
    # TestClient() without a `with` block never sends lifespan events, so
    # main.py's @app.on_event("startup") (nginx auto-publish) never runs —
    # verified against this FastAPI/Starlette version before relying on it.
    return TestClient(m.app), cache


def test_404_when_no_screenshot_yet(client):
    c, _cache = client
    resp = c.get("/site/never-captured/screenshot")
    assert resp.status_code == 404


def test_404_for_traversal_attempt(client):
    c, _cache = client
    resp = c.get("/site/..%2f..%2fetc%2fpasswd/screenshot")
    assert resp.status_code in (404, 400)


def test_200_serves_png_with_headers(client):
    c, cache = client
    screenshots.record(cache, "demo", b"\x89PNG" + b"0" * 60000, "fp-1", ok=True)

    resp = c.get("/site/demo/screenshot")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.headers["cache-control"] == "no-cache"
    assert resp.headers["x-captured-at"]
    assert resp.content.startswith(b"\x89PNG")


def test_failed_capture_still_serves_previous_png(client):
    c, cache = client
    screenshots.record(cache, "demo", b"\x89PNG" + b"0" * 60000, "fp-1", ok=True)
    screenshots.record(cache, "demo", None, "fp-2", ok=False)

    resp = c.get("/site/demo/screenshot")
    assert resp.status_code == 200
    assert resp.content.startswith(b"\x89PNG")
