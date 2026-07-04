# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.api tests — GET/POST /exposure/{vhost}."""
import importlib, sys
from pathlib import Path
from fastapi.testclient import TestClient
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common")); sys.path.insert(0, str(ROOT / "packages" / "secubox-exposure"))

def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPOSURE_SNIPPET_DIR", str(tmp_path / "snip"))
    import api.reach as r; importlib.reload(r)
    import api.main as m; importlib.reload(m)
    monkeypatch.setattr(m, "_reload_nginx", lambda: True)     # no live reload in tests
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app)

def test_post_sets_reach_and_writes_snippet(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.post("/exposure/z.example", json={"reach": "lan", "mesh": True, "tor": False})
    assert r.status_code == 200
    body = r.json()
    assert body["reach"] == "lan" and body["mesh"] is True
    snip = (tmp_path / "snip" / "z.example.conf").read_text()
    assert "allow 10.10.0.0/24;" in snip and "deny all;" in snip

def test_get_reflects_written_state(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    c.post("/exposure/z.example", json={"reach": "localhost", "mesh": False, "tor": False})
    got = c.get("/exposure/z.example").json()
    assert got["reach"] == "localhost"

def test_post_rejects_bad_reach(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.post("/exposure/z.example", json={"reach": "moon", "mesh": False, "tor": False}).status_code == 422
