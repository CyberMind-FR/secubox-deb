# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from pathlib import Path

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


def test_observe_systemctl_execution_failure_is_none_not_false():
    # rc=None = la commande n'a PAS pu s'exécuter (OSError/timeout dans
    # _run_cmd) — indistinguable d'un rc!=0 authentique si on ne traite pas
    # ce cas à part. Doit rester None, jamais un False fabriqué.
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (None, ""),
        ("systemctl", "is-active", "secubox-lyrion.service"): (None, ""),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (None, ""),
    })
    a = observe(NATIVE, run=run, routes=set())
    assert a.enabled is None
    assert a.active is None
    assert a.rss_kb is None


def test_observe_systemctl_genuine_rc1_is_false_not_none():
    # Contrepartie du test précédent : un rc=1 AUTHENTIQUE (la commande s'est
    # exécutée et a répondu "disabled"/"inactive") doit rester un vrai False,
    # pas être confondu avec l'échec d'exécution.
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (1, "disabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (3, "inactive\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(NATIVE, run=run, routes=set())
    assert a.enabled is False
    assert a.active is False


def test_load_routes_corrupt_file_is_none_not_empty(tmp_path):
    # Un JSON corrompu (ex. écriture concurrente par HAProxy) est indéterminable,
    # pas "aucune route" : ne pas fabriquer un set() vide qui masquerait l'erreur.
    p = tmp_path / "haproxy-routes.json"
    p.write_text("{not valid json")
    assert load_routes(p) is None


def test_load_routes_unreadable_file_is_none_not_empty(tmp_path, monkeypatch):
    p = tmp_path / "haproxy-routes.json"
    p.write_text(json.dumps(["peertube.gk2.secubox.in"]))

    def _raise(*_a, **_kw):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", _raise)
    assert load_routes(p) is None


def test_observe_portal_routed_none_when_routes_undeterminable(monkeypatch):
    # Si load_routes() ne peut pas déterminer les routes (fichier présent mais
    # illisible/corrompu → None), portal_routed doit rester None — surtout pas
    # False, qui laisserait croire "pas routé".
    import api.observe as observe_mod
    monkeypatch.setattr(observe_mod, "load_routes", lambda: None)
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-peertube.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-peertube.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-peertube.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(LXC, run=run)
    assert a.portal_routed is None


def test_load_routes_untraversable_parent_is_none_not_crash(tmp_path):
    """Cas RÉEL de la board : /etc/secubox/waf est 0750 root:root alors que
    haproxy-routes.json est 0644 — le fichier est lisible, le répertoire non
    traversable. `.exists()` lève alors PermissionError. Le laisser hors du try
    remontait un 500 sur GET /status. Inconnu ne doit ni mentir ni planter."""
    import os
    waf = tmp_path / "waf"
    waf.mkdir()
    routes = waf / "haproxy-routes.json"
    routes.write_text(json.dumps({"peertube.gk2.secubox.in": ["127.0.0.1", 9000]}))
    os.chmod(waf, 0o000)          # parent non traversable
    try:
        assert load_routes(routes) is None    # indéterminable, pas set(), pas d'exception
    finally:
        os.chmod(waf, 0o755)      # sinon tmp_path n'est pas nettoyable
