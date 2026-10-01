# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Un module LXC qui tourne n'est plus annoncé endormi par l'API (#1795).

L'API tourne sous le compte `secubox` : `lxc-ls -f` y voit zéro conteneur et
`lxc-info` échoue. Le repli lit /sys/fs/cgroup/lxc.payload.<nom>.
"""
from api.manifest import Manifest
from api.observe import is_on, observe, observe_all
from api.web import _build_status_payload

PT = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
              units=(), lxc="peertube", lifecycle="on-demand")
GT = Manifest(id="gitea", category="dev", runtime="lxc", exposure="lan",
              units=(), lxc="gitea", lifecycle="on-demand")


def _cgroup_v2(racine, *conteneurs):
    (racine / "cgroup.controllers").write_text("cpu memory pids\n")
    for c in conteneurs:
        (racine / f"lxc.payload.{c}").mkdir()


def _run_sans_privilege(argv):
    # Contexte de l'API : lxc-ls ne liste RIEN (en-tête seul), lxc-info échoue.
    if argv == ["lxc-ls", "-f"]:
        return 0, "NAME STATE AUTOSTART GROUPS IPV4 IPV6 UNPRIVILEGED\n"
    return 1, ""


def test_api_voit_le_conteneur_qui_tourne(_cgroup_neutre):
    _cgroup_v2(_cgroup_neutre, "peertube")
    a = observe_all({"peertube": PT, "gitea": GT}, run=_run_sans_privilege, routes=set())
    assert a["peertube"].lxc_running is True and is_on(a["peertube"])
    assert a["gitea"].lxc_running is False and not is_on(a["gitea"])


def test_observe_unitaire_meme_repli(_cgroup_neutre):
    _cgroup_v2(_cgroup_neutre, "peertube")
    assert observe(PT, run=lambda argv: (1, ""), routes=set()).lxc_running is True
    assert observe(GT, run=lambda argv: (1, ""), routes=set()).lxc_running is False


def test_lxc_ls_reste_la_source_quand_il_repond(_cgroup_neutre):
    _cgroup_v2(_cgroup_neutre)                       # aucun groupe…
    def run(argv):
        if argv == ["lxc-ls", "-f"]:
            return 0, ("NAME     STATE   AUTOSTART GROUPS IPV4 IPV6 UNPRIVILEGED\n"
                       "peertube RUNNING 1         -      -    -    true\n")
        return 1, ""
    a = observe_all({"peertube": PT}, run=run, routes=set())
    assert a["peertube"].lxc_running is True       # …mais lxc-ls (root) fait foi


def test_hors_cgroup_v2_rien_n_est_fabrique(_cgroup_neutre):
    # Racine sans cgroup.controllers : l'absence de groupe ne prouve rien.
    a = observe_all({"gitea": GT}, run=_run_sans_privilege, routes=set())
    assert a["gitea"].lxc_running is None


def test_nom_suspect_jamais_suivi(_cgroup_neutre):
    _cgroup_v2(_cgroup_neutre)
    (_cgroup_neutre / "lxc.payload.x").mkdir()
    for nom in ("../x", "a/b", ".cache"):
        m = Manifest(id="z", category="dev", runtime="lxc", exposure="lan", units=(), lxc=nom)
        assert observe_all({"z": m}, run=_run_sans_privilege, routes=set())["z"].lxc_running is None


def test_la_carte_du_hall_lit_up(_cgroup_neutre):
    _cgroup_v2(_cgroup_neutre, "peertube")
    actuals = observe_all({"peertube": PT, "gitea": GT}, run=_run_sans_privilege, routes=set())
    mods = {m["id"]: m for m in _build_status_payload({"peertube": PT, "gitea": GT}, actuals)["modules"]}
    assert mods["peertube"]["sleep_state"] == "up"
    assert mods["gitea"]["sleep_state"] == "asleep"
