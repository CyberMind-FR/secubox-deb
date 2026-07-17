# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.manifest import Manifest
from api.observe import Actual, is_on, load_routes, observe


def fake_run(table):
    """table: {(argv tuple): (rc, stdout)}"""
    def _run(argv):
        return table.get(tuple(argv), (1, ""))
    return _run


NATIVE = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                  units=("secubox-lyrion.service",))
LXC = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
               units=("secubox-peertube.service",), lxc="peertube",
               portal_domain="peertube.gk2.secubox.in")


def test_observe_native_enabled_and_active():
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(NATIVE, run=run, routes=set())
    assert a.enabled is True and a.active is True
    assert a.lxc_running is None and a.lxc_autostart is None
    assert a.portal_routed is None   # pas de portail déclaré


def test_observe_native_disabled():
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (1, "disabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (3, "inactive\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(NATIVE, run=run, routes=set())
    assert a.enabled is False and a.active is False


def test_observe_lxc_and_portal():
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-peertube.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-peertube.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-peertube.service", "-p", "MainPID", "--value"): (0, "0\n"),
        ("lxc-info", "-n", "peertube", "-s"): (0, "State: RUNNING\n"),
        ("lxc-info", "-n", "peertube", "-c", "lxc.start.auto"): (0, "lxc.start.auto = 1\n"),
    })
    a = observe(LXC, run=run, routes={"peertube.gk2.secubox.in"})
    assert a.lxc_running is True and a.lxc_autostart is True
    assert a.portal_routed is True


def test_lxc_state_unknown_is_none_not_false():
    # lxc-info échoue depuis le contexte non privilégié de l'API (motif connu de
    # cette box : lxc_state='absent' alors que le service répond). Inconnu doit
    # rester None — surtout pas False, qui déclencherait un faux 'à allumer'.
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-peertube.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-peertube.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-peertube.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(LXC, run=run, routes=set())
    assert a.lxc_running is None and a.lxc_autostart is None
    assert a.portal_routed is False   # portail déclaré mais absent des routes


def test_rss_read_from_mainpid(tmp_path, monkeypatch):
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "4242\n"),
    })
    status = tmp_path / "4242"
    status.mkdir()
    (status / "status").write_text("Name:\tpython3\nVmRSS:\t  123456 kB\n")
    monkeypatch.setattr("api.observe.PROC", tmp_path)
    a = observe(NATIVE, run=run, routes=set())
    assert a.rss_kb == 123456


def test_is_on_requires_enabled_and_active():
    assert is_on(Actual(enabled=True, active=True)) is True
    assert is_on(Actual(enabled=True, active=False)) is False
    assert is_on(Actual(enabled=False, active=True)) is False


def test_load_routes(tmp_path):
    p = tmp_path / "haproxy-routes.json"
    p.write_text(json.dumps({"peertube.gk2.secubox.in": ["127.0.0.1", 9000],
                             "billets.gk2.secubox.in": ["127.0.0.1", 8910]}))
    assert load_routes(p) == {"peertube.gk2.secubox.in", "billets.gk2.secubox.in"}


def test_load_routes_missing_file_is_empty(tmp_path):
    assert load_routes(tmp_path / "absent.json") == set()
