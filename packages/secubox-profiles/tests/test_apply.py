# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.apply import apply_plan, rollback_to
from api.diff import START, STOP, Change
from api.manifest import Manifest
from api.observe import Actual


def _m(mid, protected=False):
    return Manifest(id=mid, category="infra", runtime="native",
                    exposure="lan", units=(f"{mid}.service",), protected=protected)


def _run_ok(calls):
    def run(argv):
        calls.append(argv)
        return 0, ""
    return run


def test_dry_run_acts_on_nothing(tmp_path):
    calls = []
    plan = [Change("a", STOP, "", 50)]
    rep = apply_plan(plan, {"a": _m("a")}, {"a": Actual(active=True)},
                     run=_run_ok(calls), observe=lambda m: Actual(active=False),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=False)
    assert rep.status == "planned"
    assert calls == []  # nothing actuated


def test_apply_stops_then_starts_in_order(tmp_path):
    calls = []
    manifests = {"lo": _m("lo"), "hi": _m("hi")}
    # plan already ordered by plan_changes: stop lo, then start hi
    plan = [Change("lo", STOP, "", 10), Change("hi", START, "", 90)]
    # NOTE: is_on() requires enabled AND active (see api/observe.py) — an
    # Actual with only active= set never reads as "on", so wait_state would
    # treat "hi" as already off and loop forever awaiting next() on an
    # exhausted iterator. enabled=True makes each Actual unambiguous.
    states = {"lo": iter([Actual(enabled=True, active=False)]),
             "hi": iter([Actual(enabled=True, active=True)])}
    rep = apply_plan(plan, manifests,
                     {"lo": Actual(enabled=True, active=True),
                      "hi": Actual(enabled=True, active=False)},
                     run=_run_ok(calls), observe=lambda m: next(states[m.id]),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=True)
    assert rep.status == "applied"
    # disable (stop) issued before enable (start)
    dis = next(i for i, c in enumerate(calls) if c[:2] == ["systemctl", "disable"])
    ena = next(i for i, c in enumerate(calls) if c[:2] == ["systemctl", "enable"])
    assert dis < ena


def test_stop_of_protected_is_refused(tmp_path):
    plan = [Change("auth", STOP, "", 50)]
    import pytest
    from api.apply import ApplyError
    with pytest.raises(ApplyError):
        apply_plan(plan, {"auth": _m("auth", protected=True)},
                   {"auth": Actual(active=True)}, run=_run_ok([]),
                   observe=lambda m: Actual(active=False), now="t", routes={},
                   snap_root=tmp_path, audit_path=tmp_path / "audit.log", apply=True)


def test_failure_at_module_k_rolls_back_prior(tmp_path):
    # plan: stop a (ok), stop b (its wait never converges → failure) → a restored.
    calls = []
    manifests = {"a": _m("a"), "b": _m("b")}
    plan = [Change("a", STOP, "", 10), Change("b", STOP, "", 20)]

    def observe(m):
        # enabled=True is required so is_on() genuinely reads "on"/"off" —
        # with only active= set, is_on() (enabled AND active) would read
        # both as already-off, "b" would falsely converge on the first
        # probe, and the whole plan would apply with nothing to roll back.
        if m.id == "a":
            return Actual(enabled=True, active=False)   # a converges to off
        return Actual(enabled=True, active=True)        # b never turns off → timeout

    rep = apply_plan(plan, manifests,
                     {"a": Actual(enabled=True, active=True),
                      "b": Actual(enabled=True, active=True)},
                     run=_run_ok(calls), observe=observe, now="t", routes={},
                     snap_root=tmp_path, audit_path=tmp_path / "audit.log",
                     apply=True, wait_timeout=0)
    assert rep.status == "rolled_back"
    assert "b" in rep.failed
    # a was rolled back → re-enabled (started again)
    assert ["systemctl", "enable", "a.service"] in calls


def test_rollback_never_stops_a_protected_module(tmp_path):
    # plan: start protected "auth" (pre-state off, converges immediately),
    # then stop "b" whose wait never converges (wait_timeout=0) → failure.
    # Rollback must reverse "auth" toward its pre-state (off) WITHOUT ever
    # issuing a STOP against it — a protected module must never be stopped,
    # not even on the rollback path.
    calls = []
    manifests = {"auth": _m("auth", protected=True), "b": _m("b")}
    plan = [Change("auth", START, "", 90), Change("b", STOP, "", 20)]

    def observe(m):
        if m.id == "auth":
            # is_on() needs enabled AND active — both True reads as "on",
            # so the forward START converges on the very first probe.
            return Actual(enabled=True, active=True)
        # "b" never turns off → wait_state times out (wait_timeout=0).
        return Actual(enabled=True, active=True)

    rep = apply_plan(plan, manifests,
                     {"auth": Actual(enabled=True, active=False),
                      "b": Actual(enabled=True, active=True)},
                     run=_run_ok(calls), observe=observe, now="t", routes={},
                     snap_root=tmp_path, audit_path=tmp_path / "audit.log",
                     apply=True, wait_timeout=0)
    assert rep.status == "rolled_back"
    assert "b" in rep.failed
    assert ["systemctl", "disable", "auth.service"] not in calls
    assert not any(c[0] == "lxc-stop" and "auth" in c for c in calls)
    # the forward START itself is untouched (left running is always safe)
    assert ["systemctl", "enable", "auth.service"] in calls


def test_rollback_timeout_not_counted_as_success(tmp_path):
    # plan: stop "a" (succeeds), then stop "b" whose wait never converges
    # (wait_timeout=0) → failure. Rollback reverses "a" toward START, but
    # its own wait_state never converges either → must NOT be recorded as
    # a successful rollback.
    calls = []
    manifests = {"a": _m("a"), "b": _m("b")}
    plan = [Change("a", STOP, "", 10), Change("b", STOP, "", 20)]

    def observe(m):
        if m.id == "a":
            # always reads "off": forward STOP converges immediately, but
            # the rollback START (want_on=True) never converges → timeout.
            return Actual(enabled=True, active=False)
        return Actual(enabled=True, active=True)  # "b" never turns off

    rep = apply_plan(plan, manifests,
                     {"a": Actual(enabled=True, active=True),
                      "b": Actual(enabled=True, active=True)},
                     run=_run_ok(calls), observe=observe, now="t", routes={},
                     snap_root=tmp_path, audit_path=tmp_path / "audit.log",
                     apply=True, wait_timeout=0)
    assert rep.status == "rolled_back"
    assert "b" in rep.failed
    assert "a" not in rep.rolled_back
    # the rollback START was attempted even though it timed out
    assert ["systemctl", "enable", "a.service"] in calls


def test_rollback_to_restores_snapshot_state(tmp_path):
    # snapshot says "a" should be on, but "a" is currently observed off →
    # rollback_to must build/apply a plan that starts it.
    manifests = {"a": _m("a")}
    snap = {"ts": "t0", "modules": {"a": {"on": True}}}

    calls = []
    rep = rollback_to(snap, manifests, {"a": Actual(enabled=True, active=False)},
                      run=_run_ok(calls), observe=lambda m: Actual(enabled=True, active=True),
                      now="t", routes={}, snap_root=tmp_path / "applied",
                      audit_path=tmp_path / "audit.log", apply=True)
    assert rep.status == "applied"
    assert ["systemctl", "enable", "a.service"] in calls

    # dry-run must actuate nothing.
    dry_calls = []
    dry_rep = rollback_to(snap, manifests, {"a": Actual(enabled=True, active=False)},
                          run=_run_ok(dry_calls), observe=lambda m: Actual(enabled=True, active=True),
                          now="t", routes={}, snap_root=tmp_path / "dry",
                          audit_path=tmp_path / "audit-dry.log", apply=False)
    assert dry_rep.status == "planned"
    assert dry_calls == []


def test_start_of_condition_gated_native_module_is_not_a_failure(tmp_path):
    # hexo-like: START issued, but its systemd start-condition fails so it never
    # goes active. enable --now succeeded → not an actuation failure → no rollback.
    calls = []
    manifests = {"hexo": _m("hexo")}
    plan = [Change("hexo", START, "", 50)]

    def run(argv):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"] and "ConditionResult" in argv:
            return 0, "no\n"
        return 0, ""

    rep = apply_plan(plan, manifests, {"hexo": Actual(enabled=False, active=False)},
                     run=run, observe=lambda m: Actual(enabled=True, active=False),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=True, wait_timeout=0)
    assert rep.status == "applied"          # NOT rolled_back
    assert rep.changed == ["hexo"] and rep.failed == []


def test_slow_stop_that_reaches_state_within_derived_timeout_is_success(tmp_path):
    # metrics-like: its stop command "times out" (systemd TimeoutStopSec long),
    # but the observed state reaches OFF within the derived timeout -> success,
    # NO rollback. The command rc is irrelevant; wait_state arbitrates.
    from api.observe import Actual
    calls = []

    def run(argv):
        calls.append(argv)
        # derived_timeout asks for TimeoutStopUSec -> report a generous 90s so
        # the (single, immediate) observation below is well inside the window.
        if argv[:2] == ["systemctl", "show"] and "TimeoutStopUSec" in argv:
            return 0, "1min 30s\n"
        return 0, ""

    manifests = {"metrics": _m("metrics")}
    plan = [Change("metrics", STOP, "", 50)]
    rep = apply_plan(plan, manifests, {"metrics": Actual(enabled=True, active=True)},
                     run=run, observe=lambda m: Actual(enabled=False, active=False),
                     now="t", routes={}, snap_root=tmp_path,
                     audit_path=tmp_path / "audit.log", apply=True)
    assert rep.status == "applied"
    assert rep.changed == ["metrics"] and rep.failed == []


def test_apply_uses_derived_timeout_not_flat_30(tmp_path):
    # A stop that only reaches OFF after the monotonic clock passes 30s must
    # still SUCCEED, because the module's derived timeout (TimeoutStopUSec 90s
    # + 15 margin = 105) exceeds 30. With the OLD flat wait_timeout=30 this
    # would time out and roll back. The injected clock proves wait_state waited
    # past 30 — the load-bearing proof the happy-path test can't give.
    from api.observe import Actual
    def run(argv):
        if argv[:2] == ["systemctl", "show"] and "TimeoutStopUSec" in argv:
            return 0, "1min 30s\n"          # -> derived_timeout = 105
        return 0, ""
    probes = {"n": 0}
    def observe(m):
        probes["n"] += 1
        on = probes["n"] < 4                # ON for 3 probes, then OFF at the 4th
        return Actual(enabled=on, active=on)
    ticks = iter([0.0, 10.0, 20.0, 30.0, 40.0, 50.0])  # monotonic clock
    manifests = {"metrics": _m("metrics")}
    plan = [Change("metrics", STOP, "", 50)]
    rep = apply_plan(plan, manifests, {"metrics": Actual(enabled=True, active=True)},
                     run=run, observe=observe, now="t", routes={},
                     snap_root=tmp_path, audit_path=tmp_path / "audit.log",
                     apply=True, sleep=lambda s: None, clock=lambda: next(ticks))
    assert rep.status == "applied"          # converged at t=30<105; flat-30 would have rolled_back
