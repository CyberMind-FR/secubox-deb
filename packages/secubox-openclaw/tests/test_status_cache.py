# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import importlib
from fastapi.testclient import TestClient
def _load(monkeypatch):
    import api.main as m; importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m

def test_status_single_flight(monkeypatch):
    m = _load(monkeypatch); calls = {"n": 0}
    def counting(sub, *a, **k):
        if list(sub[:1]) == ["status"]: calls["n"] += 1
        return (True, '{"running":true,"installed":true,"ip":"10.100.0.41","tools":{"nmap":true,"dig":true,"whois":true,"curl":true}}', "")
    monkeypatch.setattr(m, "ctl", counting)
    c = TestClient(m.app)
    c.get("/status"); c.get("/status")
    assert calls["n"] == 1                      # 2nd served from cache
    m._invalidate_stats(); c.get("/status")
    assert calls["n"] == 2
