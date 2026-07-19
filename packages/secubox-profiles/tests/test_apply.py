# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.apply import apply_plan
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
    assert ["systemctl", "enable", "--now", "a.service"] in calls
