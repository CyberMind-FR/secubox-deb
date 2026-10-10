# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2253 : sites-enabled doit contenir des LIENS vers sites-available. Les copies (laissées par `sed -i` ou `os.replace` sur un lien) sont adoptées :
ce que nginx charge est la référence, sauvegardée avant, avec retour arrière si `nginx -t` échoue."""
import os
from pathlib import Path

from api import nginxrelink


def banc(tmp_path):
    sa, se, sv = tmp_path / "sites-available", tmp_path / "sites-enabled", tmp_path / "sauvegardes"
    for d in (sa, se, sv):
        d.mkdir()
    return sa, se, sv


def faux_run(rcs):
    appels = []

    def run(argv):
        appels.append(argv)
        return (rcs.pop(0) if rcs else 0), ""
    run.appels = appels
    return run


def test_plan_distingue_lier_adopter_deplacer_et_ignore_liens_et_sauvegardes(tmp_path):
    sa, se, sv = banc(tmp_path)
    (sa / "identique.conf").write_text("A\n")
    (se / "identique.conf").write_text("A\n")                       # copie fidèle
    (sa / "differe.conf").write_text("ancien\n")
    (se / "differe.conf").write_text("celui que nginx charge\n")     # copie plus récente
    (se / "orphelin.conf").write_text("seul\n")                     # aucune version dans sites-available
    (sa / "lien.conf").write_text("L\n")
    (se / "lien.conf").symlink_to("../sites-available/lien.conf")   # déjà un lien : rien à faire
    (se / "vieux.conf.bak").write_text("x\n")
    (se / "autre.conf.avant-secubox-hosts").write_text("x\n")
    actions = {a["nom"]: a["action"] for a in nginxrelink.plan(se, sa)}
    assert actions == {"identique.conf": "lier", "differe.conf": "adopter", "orphelin.conf": "deplacer"}


def test_apply_remplace_les_copies_par_des_liens_et_sauvegarde_avant(tmp_path):
    sa, se, sv = banc(tmp_path)
    (sa / "differe.conf").write_text("ancien\n")
    (se / "differe.conf").write_text("celui que nginx charge\n")
    (se / "orphelin.conf").write_text("seul\n")
    run = faux_run([0, 0])
    rep = nginxrelink.apply(nginxrelink.plan(se, sa), se, sa, sv, run)
    assert rep["relies"] == ["differe.conf", "orphelin.conf"] and rep["recharge"] is True and rep["retour_arriere"] is False
    for nom in ("differe.conf", "orphelin.conf"):
        assert (se / nom).is_symlink() and os.readlink(se / nom) == f"../sites-available/{nom}"
    assert (sa / "differe.conf").read_text() == "celui que nginx charge\n"            # la copie (ce que nginx chargeait) est adoptée
    assert (sa / "orphelin.conf").read_text() == "seul\n"
    passe = next(p for p in sv.iterdir() if p.name.startswith("relink-"))
    assert (passe / "available" / "differe.conf").read_text() == "ancien\n"            # l'ancienne version est gardée, hors de sites-enabled
    assert (passe / "enabled" / "differe.conf").read_text() == "celui que nginx charge\n"
    assert run.appels == [["nginx", "-t"], ["systemctl", "reload", "nginx"]]


def test_retour_arriere_si_nginx_t_echoue(tmp_path):
    sa, se, sv = banc(tmp_path)
    (sa / "differe.conf").write_text("ancien\n")
    (se / "differe.conf").write_text("celui que nginx charge\n")
    (se / "orphelin.conf").write_text("seul\n")
    run = faux_run([1])
    rep = nginxrelink.apply(nginxrelink.plan(se, sa), se, sa, sv, run)
    assert rep["retour_arriere"] is True and rep["recharge"] is False
    assert not (se / "differe.conf").is_symlink() and (se / "differe.conf").read_text() == "celui que nginx charge\n"
    assert (sa / "differe.conf").read_text() == "ancien\n"                              # sites-available rendu tel quel
    assert (se / "orphelin.conf").read_text() == "seul\n" and not (sa / "orphelin.conf").exists()
    assert ["systemctl", "reload", "nginx"] not in run.appels


def test_rien_a_faire_ne_recharge_pas(tmp_path):
    sa, se, sv = banc(tmp_path)
    (sa / "a.conf").write_text("A\n")
    (se / "a.conf").symlink_to("../sites-available/a.conf")
    run = faux_run([])
    rep = nginxrelink.apply(nginxrelink.plan(se, sa), se, sa, sv, run)
    assert rep["relies"] == [] and run.appels == [] and list(sv.iterdir()) == []


def test_une_cible_deja_liee_a_ailleurs_n_est_jamais_ecrasee(tmp_path):
    sa, se, sv = banc(tmp_path)
    (sa / "a.conf").symlink_to(tmp_path / "ailleurs.conf")           # la « version » d'available est elle-même un lien : on n'écrit pas à travers
    (tmp_path / "ailleurs.conf").write_text("intact\n")
    (se / "a.conf").write_text("copie\n")
    actions = nginxrelink.plan(se, sa)
    assert [a["action"] for a in actions] == ["refuser"]
    nginxrelink.apply(actions, se, sa, sv, faux_run([]))
    assert (tmp_path / "ailleurs.conf").read_text() == "intact\n" and not (se / "a.conf").is_symlink()
