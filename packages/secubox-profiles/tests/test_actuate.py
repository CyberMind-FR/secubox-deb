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


def _lxc_root_with_config(tmp_path, name, autostart="1"):
    """Prépare <tmp>/<name>/config avec une ligne lxc.start.auto — mime le vrai
    fichier de conteneur (/data/lxc/<name>/config sur la board)."""
    d = tmp_path / name
    d.mkdir()
    (d / "config").write_text(
        f"lxc.uts.name = {name}\nlxc.start.auto = {autostart}\nlxc.net.0.type = veth\n")
    return tmp_path


def test_lxc_stop_stops_and_clears_autostart(tmp_path):
    calls = []
    root = _lxc_root_with_config(tmp_path, "lyrion", autostart="1")
    order = actuate(Change("l", STOP, "", 50),
                    _m("l", runtime="lxc", lxc="lyrion", units=("secubox-lyrion.service",)),
                    run=_ok_run(calls), lxc_root=root)
    assert ["lxc-stop", "-n", "lyrion"] in calls
    # autostart cleared by EDITING the container config file (not lxc-update-config).
    assert "lxc.start.auto = 0" in (root / "lyrion" / "config").read_text()
    # host API unit stopped too — decoupled from the container on the real board.
    assert ["systemctl", "disable", "--now", "secubox-lyrion.service"] in calls
    # autostart=0 BEFORE lxc-stop — else secubox-watchdog revives the container.
    assert order.index("lxc:autostart:0") < order.index("lxc:stop")


def test_lxc_start_starts_container_then_host_unit(tmp_path):
    calls = []
    root = _lxc_root_with_config(tmp_path, "lyrion", autostart="0")
    order = actuate(Change("l", START, "", 50),
                    _m("l", runtime="lxc", lxc="lyrion", units=("secubox-lyrion.service",)),
                    run=_ok_run(calls), lxc_root=root)
    assert ["lxc-start", "-n", "lyrion"] in calls
    assert "lxc.start.auto = 1" in (root / "lyrion" / "config").read_text()
    assert ["systemctl", "enable", "--now", "secubox-lyrion.service"] in calls
    # container up BEFORE the host API that depends on it
    assert order.index("lxc:start") < order.index("systemd:enable")


def test_lxc_autostart_edit_preserves_other_config_lines(tmp_path):
    calls = []
    root = _lxc_root_with_config(tmp_path, "lyrion", autostart="1")
    actuate(Change("l", STOP, "", 50),
            _m("l", runtime="lxc", lxc="lyrion", units=("secubox-lyrion.service",)),
            run=_ok_run(calls), lxc_root=root)
    cfg = (root / "lyrion" / "config").read_text()
    assert "lxc.uts.name = lyrion" in cfg and "lxc.net.0.type = veth" in cfg
    assert cfg.count("lxc.start.auto") == 1  # single canonical line, no dup


def test_portal_stop_removes_route_before_backend(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"lyrion.gk2.secubox.in": ["127.0.0.1", 9000],
                                  "other.example": ["10.0.0.1", 80]}))
    root = _lxc_root_with_config(tmp_path, "lyrion", autostart="1")
    calls = []
    order = actuate(Change("l", STOP, "", 50),
                    _m("l", runtime="lxc", lxc="lyrion", portal="lyrion.gk2.secubox.in"),
                    run=_ok_run(calls), route_value=None, routes_path=routes, lxc_root=root)
    # route removed
    left = json.loads(routes.read_text())
    assert "lyrion.gk2.secubox.in" not in left and "other.example" in left
    # portal removed BEFORE the runtime is torn down (host API first, then lxc)
    assert order.index("portal:remove") < order.index("systemd:disable")


def test_portal_start_restores_route_from_value(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"other.example": ["10.0.0.1", 80]}))
    root = _lxc_root_with_config(tmp_path, "lyrion", autostart="0")
    actuate(Change("l", START, "", 50),
            _m("l", runtime="lxc", lxc="lyrion", portal="lyrion.gk2.secubox.in"),
            run=_ok_run([]), route_value=["127.0.0.1", 9000], routes_path=routes, lxc_root=root)
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


def test_condition_failed_detects_gated_native_unit():
    from api.actuate import condition_failed

    def run(argv):
        if argv[:2] == ["systemctl", "show"] and "ConditionResult" in argv:
            return 0, "no\n"   # systemd start-condition failed
        return 0, ""
    assert condition_failed(_m("hexo"), run) is True


def test_condition_failed_false_when_condition_ok():
    from api.actuate import condition_failed
    assert condition_failed(_m("x"), lambda a: (0, "yes\n")) is False


def test_condition_failed_false_for_lxc():
    from api.actuate import condition_failed
    # LXC/portal modules have no systemd start-condition; never gated.
    called = []
    condition_failed(_m("l", runtime="lxc", lxc="l"), lambda a: (called.append(a), (0, "no"))[1])
    assert not called  # short-circuits on runtime != native
