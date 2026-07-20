# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests secubox-waker (activator : splash + one-wake lock + budget)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_waker_up_backend_signals_proxy(monkeypatch, tmp_path):
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=True, active=True))
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 200 and r.headers.get("X-Sbx-Wake") == "up"


def test_waker_down_backend_serves_splash_and_fires_one_wake(monkeypatch, tmp_path):
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=False, active=False))
    fired = []
    monkeypatch.setattr(waker, "_fire_wake", lambda mid: fired.append(mid))
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 503
    assert "Retry-After" in r.headers and r.headers["Cache-Control"] == "no-store"
    assert fired == ["demo"]                 # exactly one wake fired


def test_waker_unknown_vhost_404(monkeypatch, tmp_path):
    import api.waker as waker
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    c = TestClient(waker.app)
    assert c.get("/_wake/nope.gk2").status_code == 404
