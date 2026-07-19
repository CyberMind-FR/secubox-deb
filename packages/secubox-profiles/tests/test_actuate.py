# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

import pytest

from api.actuate import ActuationError, actuate, wait_state
from api.diff import START, STOP, Change
from api.manifest import Manifest
from api.observe import Actual


def _m(mid, runtime="native", units=("u.service",), lxc=None, portal=None):
    return Manifest(id=mid, category="infra", runtime=runtime, exposure="lan",
                    units=tuple(units), lxc=lxc, portal_domain=portal)


def _ok_run(calls):
    def run(argv):
        calls.append(argv)
        return 0, ""
    return run


def test_native_start_enables_now(tmp_path):
    calls = []
    actuate(Change("x", START, "", 50), _m("x"), run=_ok_run(calls))
    assert ["systemctl", "enable", "--now", "u.service"] in calls


def test_native_stop_disables_now():
    calls = []
    actuate(Change("x", STOP, "", 50), _m("x"), run=_ok_run(calls))
    assert ["systemctl", "disable", "--now", "u.service"] in calls


def test_lxc_stop_stops_and_clears_autostart():
    calls = []
    actuate(Change("l", STOP, "", 50), _m("l", runtime="lxc", lxc="lyrion"),
            run=_ok_run(calls))
    assert ["lxc-stop", "-n", "lyrion"] in calls
    # autostart cleared via lxc-update-config (0) — exact tool checked by impl
    assert any("lxc" in " ".join(c) and "0" in " ".join(c) for c in calls)


def test_portal_stop_removes_route_before_backend(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"lyrion.gk2.secubox.in": ["127.0.0.1", 9000],
                                  "other.example": ["10.0.0.1", 80]}))
    calls = []
    order = actuate(Change("l", STOP, "", 50),
                    _m("l", runtime="lxc", lxc="lyrion", portal="lyrion.gk2.secubox.in"),
                    run=_ok_run(calls), route_value=None, routes_path=routes)
    # route removed
    left = json.loads(routes.read_text())
    assert "lyrion.gk2.secubox.in" not in left and "other.example" in left
    # portal removed BEFORE the lxc backend stopped
    assert order.index("portal:remove") < order.index("lxc:stop")


def test_portal_start_restores_route_from_value(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"other.example": ["10.0.0.1", 80]}))
    actuate(Change("l", START, "", 50),
            _m("l", runtime="lxc", lxc="lyrion", portal="lyrion.gk2.secubox.in"),
            run=_ok_run([]), route_value=["127.0.0.1", 9000], routes_path=routes)
    got = json.loads(routes.read_text())
    assert got["lyrion.gk2.secubox.in"] == ["127.0.0.1", 9000]


def test_failed_command_raises():
    def bad_run(argv):
        return 1, "boom"
    with pytest.raises(ActuationError):
        actuate(Change("x", START, "", 50), _m("x"), run=bad_run)


def test_command_that_cannot_run_raises():
    def dead_run(argv):
        return None, ""
    with pytest.raises(ActuationError):
        actuate(Change("x", START, "", 50), _m("x"), run=dead_run)


def test_wait_state_converges():
    seq = iter([Actual(enabled=True, active=False), Actual(enabled=True, active=True)])
    ticks = []
    ok = wait_state(_m("x"), True, observe=lambda m: next(seq),
                    sleep=lambda s: ticks.append(s), now=iter([0, 1, 2]).__next__,
                    timeout=30, poll=1)
    assert ok is True


def test_wait_state_times_out():
    ok = wait_state(_m("x"), True, observe=lambda m: Actual(active=False),
                    sleep=lambda s: None, now=iter([0, 10, 20, 31]).__next__,
                    timeout=30, poll=10)
    assert ok is False
