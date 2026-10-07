# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
import api.main as m

def test_status_reports_role_and_socks(monkeypatch):
    monkeypatch.setattr(m.role, "detect", lambda probe=None: {"role":"master","tier":1,"dns_resolver":True,"lan_ip":"192.168.1.200"})
    monkeypatch.setattr(m.config, "load", lambda *a, **k: {"socks_endpoint":"192.168.1.200:9050","transparent":True,"wpad_domain":"gk2.secubox.in","pac_url":"","role":"auto"})
    c = TestClient(m.app)
    r = c.get("/status")
    assert r.status_code == 200
    d = r.json()
    assert d["role"] == "master" and d["socks_endpoint"] == "192.168.1.200:9050" and d["transparent"] is True

def test_transparent_toggle_delegates(monkeypatch):
    called = {}

    def fake_ctl(*a, **k):
        called["args"] = a
        return (0, "")

    monkeypatch.setattr(m, "_ctl", fake_ctl)
    c = TestClient(m.app)
    r = c.post("/transparent", json={"on": True})
    assert r.status_code == 200 and r.json().get("ok") is True
    assert "torctl" in " ".join(called["args"][0])
