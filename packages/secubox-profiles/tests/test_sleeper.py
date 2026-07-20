# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests secubox-sleeper (should_sleep + run_once)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import json

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
    # actuate() also persists the removed route to a durable store at a hardcoded
    # default (portal_routes.REMEMBER_FILE) not threaded through apply_plan —
    # retarget it too, same technique, to keep the test off /var/lib/secubox.
    monkeypatch.setitem(_actuate.actuate.__kwdefaults__, "remember_path",
                        tmp_path / "portal-routes.json")
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


def test_sleeper_daemon_wires_serve_with_production_deps(monkeypatch, tmp_path):
    """api.sleeper_daemon.main_async must forward to sleeper.serve with a
    kwarg set matching serve()'s signature (root/interval/sleep/observe_all/
    signal_reader/hint_probe/run/observe/now/stamp/tick_limit) — a stray
    rename on either side would only blow up at runtime (no static check
    across the two modules), so this test locks the wiring."""
    import asyncio

    import api.sleeper_daemon as daemon

    captured: dict = {}

    async def fake_serve(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(daemon.sleeper, "serve", fake_serve)

    asyncio.run(daemon.main_async(root=tmp_path, interval=5.0, tick_limit=1))

    assert captured["root"] == tmp_path
    assert captured["interval"] == 5.0
    assert captured["tick_limit"] == 1
    assert captured["observe_all"] is daemon.observe_all
    assert captured["observe"] is daemon.observe
    assert captured["signal_reader"] is daemon._signal_reader
    assert captured["hint_probe"] is daemon._hint_probe
    assert captured["run"] is daemon._run
    assert captured["now"] is daemon.time.time
    assert captured["stamp"] is daemon._now_iso
    assert asyncio.iscoroutinefunction(captured["sleep"]) or callable(captured["sleep"])


def test_sleeper_daemon_signal_reader_missing_file_is_safe_empty(monkeypatch, tmp_path):
    """No sbxwaf snapshot on disk yet (fresh boot, sbxwaf not started, or
    --vhost-signals disabled) must return {} so should_sleep() never gets a
    fabricated signal and therefore never sleeps a module on a missing
    file — same best-effort contract as sleeper._read_wake_locked."""
    import api.sleeper_daemon as daemon
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", tmp_path / "nope.json")
    assert daemon._signal_reader() == {}


def test_sleeper_daemon_signal_reader_corrupt_json_is_safe_empty(monkeypatch, tmp_path):
    """Half-written/corrupt JSON (read racing sbxwaf's flush) must never
    raise — best-effort => {}."""
    import api.sleeper_daemon as daemon
    path = tmp_path / "vhost-signals.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", path)
    assert daemon._signal_reader() == {}


def test_sleeper_daemon_signal_reader_unexpected_shape_is_safe_empty(monkeypatch, tmp_path):
    """Valid JSON but not the expected {vhost: {...}} object shape (e.g. a
    bare list, or a non-dict value under a vhost key) must not blow up and
    must not smuggle a bogus Signal through."""
    import api.sleeper_daemon as daemon
    path = tmp_path / "vhost-signals.json"
    path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", path)
    assert daemon._signal_reader() == {}

    # A mix of a malformed entry (value is not a dict) and a well-formed one:
    # the malformed entry is dropped, the well-formed one still passes through
    # (front_signals.vhost_signals does its own per-field validation on the
    # rest — this reader only guards the outer {vhost: {...}} shape).
    path.write_text(json.dumps({"a.gk2": "not-a-dict", "b.gk2": {"x": 1}}), encoding="utf-8")
    assert daemon._signal_reader() == {"b.gk2": {"x": 1}}


def test_sleeper_daemon_signal_reader_reads_real_snapshot(monkeypatch, tmp_path):
    """Reads exactly the shape sbxwaf's vhostsignals.go writes and passes
    the raw per-vhost dict straight through (front_signals.vhost_signals
    does its own field validation) — this is the wiring this task adds."""
    import api.sleeper_daemon as daemon
    path = tmp_path / "vhost-signals.json"
    path.write_text(json.dumps({
        "sleepy.gk2": {"last_request_ts": 1000.0, "active_conns": 0},
        "busy.gk2": {"last_request_ts": 2000.0, "active_conns": 2},
    }), encoding="utf-8")
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", path)

    got = daemon._signal_reader()

    assert got == {
        "sleepy.gk2": {"last_request_ts": 1000.0, "active_conns": 0},
        "busy.gk2": {"last_request_ts": 2000.0, "active_conns": 2},
    }


def test_sleeper_daemon_signal_reader_feeds_wall_clock_idle_decision(monkeypatch, tmp_path):
    """End-to-end wall-clock correctness (this task's critical property):
    an old last_request_ts written as unix wall-clock seconds, read through
    _signal_reader and fed through front_signals.vhost_signals with a real
    wall-clock `now` (time.time-shaped), must compute a large positive age
    — proving the reader's output is NOT monotonic-clock-relative and that
    should_sleep() would call this vhost idle."""
    import time as time_mod

    import api.sleeper_daemon as daemon
    from api.front_signals import vhost_signals
    from api.sleeper import should_sleep
    from api.manifest import Manifest

    path = tmp_path / "vhost-signals.json"
    old_ts = time_mod.time() - 1000.0
    path.write_text(json.dumps({
        "sleepy.gk2": {"last_request_ts": old_ts, "active_conns": 0},
    }), encoding="utf-8")
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", path)

    sig = vhost_signals(reader=daemon._signal_reader, now=time_mod.time)["sleepy.gk2"]

    assert sig.last_request_age is not None and sig.last_request_age >= 999.0
    assert sig.active_conns == 0

    m = Manifest(id="sleepy", category="infra", runtime="native", exposure="public",
                units=("sleepy.service",), lifecycle="on-demand")
    assert should_sleep(m, sig, hint_idle=None, now_up=True) is True


def test_sleeper_daemon_signal_reader_merges_per_worker_snapshots(monkeypatch, tmp_path):
    """secubox-waf-ng-worker@1 and @2 each hold their OWN in-memory Begin/End
    vhost state and (since #896 final review, Fix 2) each flush their OWN
    file (vhost-signals.@1.json / @2.json) instead of clobbering a shared
    path. The reader must glob and merge: last_request_ts=max, active_conns
    =sum — a vhost fresh/active on ONE worker must never be judged idle
    just because the OTHER worker's snapshot is stale/zero (this was the
    pre-fix last-writer-wins bug: a service kept fresh on @1 could be seen
    stale in @2's snapshot -> wrong STOP of a live service)."""
    import api.sleeper_daemon as daemon

    base = tmp_path / "vhost-signals.json"  # legacy path itself absent
    (tmp_path / "vhost-signals.@1.json").write_text(json.dumps({
        "v.gk2": {"last_request_ts": 5000.0, "active_conns": 2},
    }), encoding="utf-8")
    (tmp_path / "vhost-signals.@2.json").write_text(json.dumps({
        "v.gk2": {"last_request_ts": 1000.0, "active_conns": 1},
    }), encoding="utf-8")
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", base)

    got = daemon._signal_reader()

    # max(5000, 1000)=5000 ; sum(2, 1)=3 — proves both max-pick AND
    # summation, not just "use the freshest worker's whole record".
    assert got == {"v.gk2": {"last_request_ts": 5000.0, "active_conns": 3}}


def test_sleeper_daemon_signal_reader_falls_back_to_legacy_path_when_no_per_worker_files(
    monkeypatch, tmp_path,
):
    """No @N per-worker files on disk (mono-worker deploy, or sbxwaf not yet
    restarted with the new per-instance flag) must fall back to the old
    plain path, unchanged — back-compat for #896 final review Fix 2."""
    import api.sleeper_daemon as daemon

    path = tmp_path / "vhost-signals.json"
    path.write_text(json.dumps({
        "legacy.gk2": {"last_request_ts": 42.0, "active_conns": 1},
    }), encoding="utf-8")
    monkeypatch.setattr(daemon, "VHOST_SIGNALS_PATH", path)

    assert daemon._signal_reader() == {
        "legacy.gk2": {"last_request_ts": 42.0, "active_conns": 1},
    }


def test_sleeper_daemon_hint_probe_stub_is_safe_none():
    """Documented stub: no per-module /idle route exists yet. None must
    never veto/allow a sleep decision by accident."""
    import api.sleeper_daemon as daemon
    from api.manifest import Manifest
    m = Manifest(id="x", category="infra", runtime="native", exposure="lan",
                units=("x.service",), lifecycle="on-demand")
    assert daemon._hint_probe("x", m) is None
