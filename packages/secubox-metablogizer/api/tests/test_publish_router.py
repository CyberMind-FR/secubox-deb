# packages/secubox-metablogizer/api/tests/test_publish_router.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import io
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import importlib
    import routers.publish as rp
    importlib.reload(rp)
    # Point the site root at tmp and stub privileged deps.
    monkeypatch.setattr(rp, "SITES_ROOT", tmp_path / "sites")
    (tmp_path / "sites" / "zem" / "public").mkdir(parents=True)
    monkeypatch.setattr(rp, "apply_route", lambda domain, port=8900: {"route_ok": True, "vhost": {}, "waf": {}})
    monkeypatch.setattr(rp, "provision_cert", lambda domain: {"mode": "wildcard", "detail": ""})
    monkeypatch.setattr(rp, "git_commit_push", lambda d, m: {"pushed": True, "committed": True, "commit": "abc", "reason": "ok"})
    # Bypass auth
    from secubox_core.auth import require_jwt
    app = FastAPI()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    app.include_router(rp.router)
    return TestClient(app)


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.html", "<h1>zem</h1>")
    return buf.getvalue()


def test_wizard_runs_all_steps(client):
    r = client.post("/publish/wizard",
                    data={"name": "zem"},
                    files={"file": ("site.zip", _zip_bytes(), "application/zip")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["domain"] == "zem.gk2.secubox.in"
    assert body["steps"]["content"]["index_present"] is True
    assert body["steps"]["route"]["route_ok"] is True
    assert body["steps"]["cert"]["mode"] == "wildcard"


def test_publish_route_endpoint(client):
    r = client.post("/publish/route", json={"domain": "zem.gk2.secubox.in"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["cert"]["mode"] == "wildcard"
