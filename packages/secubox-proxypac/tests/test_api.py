# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import importlib, json
from fastapi.testclient import TestClient

def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXYPAC_RULES_DIR", str(tmp_path / "rules.d"))
    monkeypatch.setenv("PROXYPAC_AUDIT", str(tmp_path / "audit.log"))
    import api.main as m
    importlib.reload(m)
    monkeypatch.setattr(m, "run_once", lambda *a, **k: True)  # no live regen in tests
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app), tmp_path

def test_add_and_list_override(tmp_path, monkeypatch):
    c, tp = _client(tmp_path, monkeypatch)
    r = c.post("/override", json={"host": "bank.example", "proxy": "direct", "address": ""})
    assert r.status_code == 200
    rules = c.get("/rules").json()["rules"]
    assert {"host": "bank.example", "directive": "DIRECT"} in rules
    assert "bank.example" in (tp / "audit.log").read_text()

def test_delete_override(tmp_path, monkeypatch):
    c, tp = _client(tmp_path, monkeypatch)
    c.post("/override", json={"host": "x.com", "proxy": "socks5", "address": "10.10.0.1:9050"})
    assert c.delete("/override/x.com").status_code == 200
    assert all(r["host"] != "x.com" for r in c.get("/rules").json()["rules"])
