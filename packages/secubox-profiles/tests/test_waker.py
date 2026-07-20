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


def test_fire_wake_reaps_child_no_zombie(monkeypatch):
    """`_fire_wake` must not leak a <defunct> zombie: without a `.wait()`
    somewhere, the child process it Popen()s is never reaped. This asserts
    the reaper daemon thread is built with target=<popen>.wait, started, and
    that invoking that target actually reaps (via a fake Popen whose .wait()
    flips a flag) — real coverage of the fix, not just an argv assertion."""
    import api.waker as waker

    class FakePopen:
        def __init__(self):
            self.waited = False

        def wait(self):
            self.waited = True

    fake = FakePopen()
    monkeypatch.setattr(waker.subprocess, "Popen", lambda *a, **k: fake)

    started: dict = {}

    class FakeThread:
        def __init__(self, target=None, daemon=None):
            started["target"] = target
            started["daemon"] = daemon

        def start(self):
            started["started"] = True
            started["target"]()  # simulate the reaper thread running

    monkeypatch.setattr(waker.threading, "Thread", FakeThread)

    waker._fire_wake("demo")

    assert started["target"] == fake.wait
    assert started["daemon"] is True
    assert started["started"] is True
    assert fake.waited is True  # reaped — no zombie left behind
