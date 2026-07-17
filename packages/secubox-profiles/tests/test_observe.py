# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from pathlib import Path

from api.manifest import Manifest
from api.observe import Actual, is_on, load_routes, observe, observe_all


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


# ---------------------------------------------------------------------------
# observe_all() — chemin batché (une commande systemctl show, une lxc-ls)
# ---------------------------------------------------------------------------

def _show_block(unit: str, *, enabled="enabled", active="active", pid="0",
                order=("Id", "UnitFileState", "ActiveState", "MainPID")) -> str:
    values = {"Id": unit, "UnitFileState": enabled, "ActiveState": active, "MainPID": pid}
    return "\n".join(f"{k}={values[k]}" for k in order)


def _lxc_ls_fancy(rows: list[tuple[str, str, str]]) -> str:
    """Rebuild `lxc-ls -f` fixed-width column output (NAME/STATE/AUTOSTART/…)
    with the SAME column widths as the real board output (captured via ssh:
    `NAME                STATE   AUTOSTART GROUPS IPV4         IPV6 UNPRIVILEGED`),
    so the parser is exercised against realistic alignment instead of
    hand-typed spacing that may not match header offsets."""
    header = (f"{'NAME':<20}{'STATE':<8}{'AUTOSTART':<10}{'GROUPS':<7}"
             f"{'IPV4':<13}{'IPV6':<5}UNPRIVILEGED")
    lines = [header]
    for name, state, autostart in rows:
        lines.append(f"{name:<20}{state:<8}{autostart:<10}{'-':<7}{'-':<13}{'-':<5}true")
    return "\n".join(lines) + "\n"


def test_observe_all_batches_a_single_systemctl_call_for_all_units():
    # LE point de la bascule : une seule commande `systemctl show`, pas une
    # boucle observe() par module (560 sous-process sur 187 modules -> 46s).
    calls = []

    def run(argv):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            blocks = [_show_block(u) for u in
                     ("secubox-a.service", "secubox-b.service", "secubox-c.service")]
            return 0, "\n\n".join(blocks)
        return 1, ""

    manifests = {
        mid: Manifest(id=mid, category="media", runtime="native", exposure="lan",
                      units=(f"secubox-{mid}.service",))
        for mid in ("a", "b", "c")
    }
    actuals = observe_all(manifests, run=run, routes=set())

    show_calls = [c for c in calls if c[:2] == ["systemctl", "show"]]
    assert len(show_calls) == 1, "must be ONE batched systemctl show, not one per module"
    for u in ("secubox-a.service", "secubox-b.service", "secubox-c.service"):
        assert u in show_calls[0]
    for mid in ("a", "b", "c"):
        assert actuals[mid].enabled is True and actuals[mid].active is True


def test_observe_all_unit_missing_from_batch_output_is_none_not_false():
    # Une unit absente du bloc renvoyé (unit inconnue de systemd, ou batch
    # qui n'a couvert qu'une partie) doit rester indéterminée — jamais un
    # False fabriqué, qui déclencherait une fausse décision "à éteindre".
    def run(argv):
        if argv[:2] == ["systemctl", "show"]:
            return 0, _show_block("secubox-lyrion.service")
        return 1, ""

    present = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                       units=("secubox-lyrion.service",))
    missing = Manifest(id="ghost", category="media", runtime="native", exposure="lan",
                       units=("secubox-ghost-unit.service",))
    actuals = observe_all({"lyrion": present, "ghost": missing}, run=run, routes=set())

    assert actuals["lyrion"].enabled is True and actuals["lyrion"].active is True
    assert actuals["ghost"].enabled is None
    assert actuals["ghost"].active is None


def test_observe_all_excludes_bare_template_units_from_the_batch():
    # secubox-toolbox-ng-worker@.service (bare template, no instance) crashes
    # `systemctl show` for the WHOLE batch when included (verified on the
    # board: aborts after the first bad unit, dropping everything after it in
    # argv). It must never reach argv, and its own state stays unknown.
    calls = []

    def run(argv):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            return 0, _show_block("secubox-lyrion.service")
        return 1, ""

    normal = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                      units=("secubox-lyrion.service",))
    template = Manifest(id="worker", category="infra", runtime="native", exposure="internal",
                        units=("secubox-toolbox-ng-worker@.service",))
    actuals = observe_all({"lyrion": normal, "worker": template}, run=run, routes=set())

    show_call = next(c for c in calls if c[:2] == ["systemctl", "show"])
    assert "secubox-toolbox-ng-worker@.service" not in show_call
    assert actuals["worker"].enabled is None
    assert actuals["worker"].active is None
    assert actuals["lyrion"].enabled is True  # unaffected


def test_observe_all_parses_block_regardless_of_property_order():
    # Observé sur la board : MainPID peut apparaître AVANT Id dans un bloc.
    # Le parsing doit être par clé, jamais par position.
    def run(argv):
        if argv[:2] == ["systemctl", "show"]:
            return 0, _show_block(
                "secubox-lyrion.service", pid="4242",
                order=("MainPID", "ActiveState", "Id", "UnitFileState"))
        return 1, ""

    m = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                 units=("secubox-lyrion.service",))
    actuals = observe_all({"lyrion": m}, run=run, routes=set())
    assert actuals["lyrion"].enabled is True
    assert actuals["lyrion"].active is True


def test_observe_all_static_unit_file_state_is_enabled_true():
    # `systemctl is-enabled` exits 0 (enabled) for UnitFileState=static — pas
    # seulement pour "enabled" littéralement (25 des 183 units réelles de la
    # board sont "static"). Un mapping naïf ufs=="enabled" mentirait ici.
    def run(argv):
        if argv[:2] == ["systemctl", "show"]:
            return 0, _show_block("secubox-adblock-sync.service", enabled="static")
        return 1, ""

    m = Manifest(id="adblock-sync", category="network", runtime="native", exposure="lan",
                 units=("secubox-adblock-sync.service",))
    actuals = observe_all({"adblock-sync": m}, run=run, routes=set())
    assert actuals["adblock-sync"].enabled is True


def test_observe_all_lxc_is_a_single_enumeration_and_missing_container_is_none():
    calls = []

    def run(argv):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            blocks = [_show_block(u) for u in
                     ("secubox-peertube.service", "secubox-ghost.service")]
            return 0, "\n\n".join(blocks)
        if argv == ["lxc-ls", "-f"]:
            return 0, _lxc_ls_fancy([("peertube", "RUNNING", "1")])
        return 1, ""

    peertube = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
                        units=("secubox-peertube.service",), lxc="peertube")
    ghost = Manifest(id="ghost", category="media", runtime="lxc", exposure="lan",
                     units=("secubox-ghost.service",), lxc="ghost-container")
    actuals = observe_all({"peertube": peertube, "ghost": ghost}, run=run, routes=set())

    lxc_calls = [c for c in calls if c[0] == "lxc-ls"]
    assert len(lxc_calls) == 1, "must be ONE lxc-ls enumeration, not one lxc-info per container"
    assert actuals["peertube"].lxc_running is True
    assert actuals["peertube"].lxc_autostart is True
    # ghost-container absent from lxc-ls output -> stays unknown, not False.
    assert actuals["ghost"].lxc_running is None
    assert actuals["ghost"].lxc_autostart is None


def test_observe_all_matches_observe_for_a_single_module(monkeypatch):
    # observe_all() doit produire le même résultat que observe() pour un
    # module donné — seul le coût change, pas le contrat.
    run_single = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    single = observe(NATIVE, run=run_single, routes=set())

    def run_batch(argv):
        if argv[:2] == ["systemctl", "show"]:
            return 0, _show_block("secubox-lyrion.service")
        return 1, ""

    batched = observe_all({"lyrion": NATIVE}, run=run_batch, routes=set())["lyrion"]
    assert batched.enabled == single.enabled
    assert batched.active == single.active


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
