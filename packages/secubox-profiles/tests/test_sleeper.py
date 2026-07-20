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
