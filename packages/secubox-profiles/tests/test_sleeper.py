# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests secubox-sleeper (should_sleep + run_once)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from api.sleeper import should_sleep
from api.front_signals import Signal
from api.manifest import Manifest


def _m(lifecycle="on-demand", wake_class="normal", protected=False):
    return Manifest(id="x", category="infra", runtime="native", exposure="lan",
                    units=("x.service",), protected=protected,
                    lifecycle=lifecycle, wake_class=wake_class)


def test_sleeps_when_idle_and_no_conns():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=0),
                        hint_idle=None, now_up=True) is True


def test_not_sleep_if_conns_open():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=2),
                        hint_idle=None, now_up=True) is False


def test_not_sleep_if_recent_request():
    assert should_sleep(_m(), Signal(last_request_age=10.0, active_conns=0),
                        hint_idle=None, now_up=True) is False


def test_module_hint_vetoes_sleep():
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=0),
                        hint_idle=False, now_up=True) is False


def test_unknown_signal_never_sleeps():
    assert should_sleep(_m(), None, hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(last_request_age=None, active_conns=0),
                        hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(last_request_age=1000.0, active_conns=None),
                        hint_idle=None, now_up=True) is False


def test_never_sleeps_non_sleepable_or_down():
    assert should_sleep(_m(lifecycle="always-on"),
                        Signal(1000.0, 0), hint_idle=None, now_up=True) is False
    assert should_sleep(_m(protected=True),
                        Signal(1000.0, 0), hint_idle=None, now_up=True) is False
    assert should_sleep(_m(), Signal(1000.0, 0), hint_idle=None, now_up=False) is False


def test_urgent_uses_longer_threshold():
    # 1000s idle: normal (threshold 900) sleeps, urgent (threshold 3600) does not
    assert should_sleep(_m(wake_class="normal"), Signal(1000.0, 0),
                        hint_idle=None, now_up=True) is True
    assert should_sleep(_m(wake_class="urgent"), Signal(1000.0, 0),
                        hint_idle=None, now_up=True) is False


def test_run_once_stops_only_idle_sleepable(tmp_path):
    from api.sleeper import run_once
    from api.front_signals import Signal
    from api.observe import Actual
    from api.manifest import Manifest
    manifests = {
        "idle1": Manifest(id="idle1", category="infra", runtime="native",
                          exposure="lan", units=("idle1.service",), lifecycle="on-demand"),
        "busy": Manifest(id="busy", category="infra", runtime="native",
                         exposure="lan", units=("busy.service",), lifecycle="on-demand"),
        "core": Manifest(id="core", category="infra", runtime="native",
                         exposure="lan", units=("core.service",), lifecycle="always-on"),
    }
    actuals = {k: Actual(enabled=True, active=True) for k in manifests}   # all up
    signals = {"idle1": Signal(1000.0, 0), "busy": Signal(5.0, 1), "core": Signal(1000.0, 0)}
    calls = []
    stopped = run_once(root=tmp_path, manifests=manifests, actuals=actuals,
                       signals=signals, hints={}, run=lambda a: (calls.append(a), (0, ""))[1],
                       observe=lambda m: Actual(enabled=False, active=False),
                       now="t", wake_locked=frozenset())
    assert stopped == ["idle1"]
    assert any(c[:2] == ["systemctl", "disable"] for c in calls)


def test_run_once_skips_wake_locked(tmp_path):
    from api.sleeper import run_once
    from api.front_signals import Signal
    from api.observe import Actual
    from api.manifest import Manifest
    manifests = {"idle1": Manifest(id="idle1", category="infra", runtime="native",
                 exposure="lan", units=("idle1.service",), lifecycle="on-demand")}
    stopped = run_once(root=tmp_path, manifests=manifests,
                       actuals={"idle1": Actual(enabled=True, active=True)},
                       signals={"idle1": Signal(1000.0, 0)}, hints={},
                       run=lambda a: (0, ""), observe=lambda m: Actual(enabled=False, active=False),
                       now="t", wake_locked=frozenset({"idle1"}))
    assert stopped == []


def test_serve_one_tick_stops_idle(tmp_path, monkeypatch):
    import asyncio
    from api.sleeper import serve
    from api.observe import Actual
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "d.toml").write_text(
        'id="d"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["d.service"]\nlifecycle="on-demand"\n[portal]\ndomain="d.gk2"\n')
    # actuate() STOPs a portal-routed module by editing the WAF routes file
    # DIRECTLY (real Path I/O, bypassing the injected `run`) at a hardcoded
    # default (api.actuate.ROUTES_FILE) — apply_plan/run_once do not thread a
    # routes_path override through. Keep this test off the real system path
    # by retargeting actuate()'s own bound default (a plain dict, restored by
    # monkeypatch on teardown) rather than touching /etc/secubox.
    import api.actuate as _actuate
    routes_file = tmp_path / "routes.json"
    routes_file.write_text("{}")
    monkeypatch.setitem(_actuate.actuate.__kwdefaults__, "routes_path", routes_file)
    calls = []

    async def go():
        await serve(root=tmp_path, interval=0, sleep=lambda s: asyncio.sleep(0),
                    observe_all=lambda ms, routes=None: {"d": Actual(enabled=True, active=True)},
                    signal_reader=lambda: {"d.gk2": {"last_request_ts": 0.0, "active_conns": 0}},
                    hint_probe=lambda mid, m: None,
                    run=lambda a: (calls.append(a), (0, ""))[1],
                    observe=lambda m: Actual(enabled=False, active=False),
                    now=lambda: 100000.0, tick_limit=1)
    asyncio.run(go())
    assert any(c[:2] == ["systemctl", "disable"] for c in calls)
