# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Etalement du demarrage des conteneurs (#1001).

23 conteneurs declaraient `lxc.start.auto = 1` SANS ordre ni delai : ils
partaient tous ensemble, chacun montant une pile systemd complete sur 4 coeurs.
Mesure au redemarrage du 2026-08-07 : charge 120, 27 jobs systemd en attente,
multi-user.target jamais atteint, HAProxy jamais lance.
"""
from pathlib import Path
from types import SimpleNamespace

from api import lxcstagger


def _m(mid, prio, lxc=None, runtime="lxc"):
    return SimpleNamespace(id=mid, priority=prio, runtime=runtime, lxc=lxc or mid)


def _cfg(root, name, auto="1", extra=""):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "config").write_text(f"lxc.uts.name = {name}\nlxc.start.auto = {auto}\n{extra}")
    return d / "config"


def test_infrastructure_starts_before_applications(tmp_path):
    """L'ordre vient de la priorite du manifeste — une seule source de verite."""
    _cfg(tmp_path, "infra"); _cfg(tmp_path, "appli")
    ms = {"infra": _m("infra", 90), "appli": _m("appli", 20)}
    rows = lxcstagger.plan(ms, lxc_path=tmp_path)
    assert [r["module"] for r in rows] == ["infra", "appli"]
    # lxc-autostart trie par ordre DECROISSANT : le plus grand passe en premier.
    assert rows[0]["order"] > rows[1]["order"]


def test_low_priority_waits_longer(tmp_path):
    """C'est le demarrage applicatif qui coute, et personne ne l'attend dans
    la seconde."""
    assert lxcstagger.delay_for(90) < lxcstagger.delay_for(20)


def test_containers_not_autostarted_are_left_alone(tmp_path):
    """Regler l'ordre d'un conteneur que personne ne demarre au boot n'a aucun
    effet et brouille la lecture du fichier."""
    _cfg(tmp_path, "manuel", auto="0")
    ms = {"manuel": _m("manuel", 50)}
    assert lxcstagger.plan(ms, lxc_path=tmp_path) == []


def test_apply_is_idempotent(tmp_path):
    """Relancer apres chaque installation ne doit produire aucun changement."""
    _cfg(tmp_path, "app")
    ms = {"app": _m("app", 40)}
    assert lxcstagger.apply(ms, lxc_path=tmp_path) == ["app"]
    assert lxcstagger.apply(ms, lxc_path=tmp_path) == []
    txt = (tmp_path / "app" / "config").read_text()
    assert txt.count("lxc.start.order") == 1, "pas de doublon"
    assert txt.count("lxc.start.delay") == 1


def test_existing_values_are_replaced_not_appended(tmp_path):
    """Les cles sont REMPLACEES, jamais dupliquees.

    L'ordre de depart est plus BAS que la priorite : un ordre plus eleve est
    desormais conserve (cf. test_a_hand_set_higher_order_is_never_demoted),
    ce test ne porte donc que sur l'ecriture elle-meme."""
    _cfg(tmp_path, "app", extra="lxc.start.order = 5\nlxc.start.delay = 1\n")
    ms = {"app": _m("app", 40)}
    lxcstagger.apply(ms, lxc_path=tmp_path)
    txt = (tmp_path / "app" / "config").read_text()
    assert txt.count("lxc.start.order") == 1 and txt.count("lxc.start.delay") == 1
    assert "= 5" not in txt and "= 40" in txt


def test_window_is_reported(tmp_path):
    """Un etalement qui repousse le dernier conteneur a dix minutes n'est pas
    un reglage, c'est une panne differee — il faut pouvoir le dire."""
    for n in ("a", "b", "c"):
        _cfg(tmp_path, n)
    ms = {n: _m(n, 20) for n in ("a", "b", "c")}
    assert lxcstagger.total_window(ms, lxc_path=tmp_path) == 3 * lxcstagger.delay_for(20)


def test_native_modules_are_ignored(tmp_path):
    ms = {"x": _m("x", 50, runtime="native")}
    assert lxcstagger.plan(ms, lxc_path=tmp_path) == []


def test_a_hand_set_higher_order_is_never_demoted(tmp_path):
    """toolbox-mitm portait order=120, pose deliberement pour passer en
    premier. La plupart des manifestes gardant la priorite par defaut (50),
    appliquer la priorite telle quelle l'aurait retrograde — cassant une
    intention dont la trace n'existe que dans ce fichier."""
    _cfg(tmp_path, "toolbox", extra="lxc.start.order = 120\n")
    ms = {"toolbox": _m("toolbox", 50)}
    row = lxcstagger.plan(ms, lxc_path=tmp_path)[0]
    assert row["order"] == 120, "un ordre manuel plus eleve doit etre conserve"
    assert row["kept_manual_order"] is True, "et la conservation doit etre signalee"


def test_a_lower_hand_set_order_is_raised(tmp_path):
    """Conserver le PLUS ELEVE, pas figer n'importe quelle valeur existante."""
    _cfg(tmp_path, "app", extra="lxc.start.order = 5\n")
    ms = {"app": _m("app", 40)}
    row = lxcstagger.plan(ms, lxc_path=tmp_path)[0]
    assert row["order"] == 40 and row["kept_manual_order"] is False
