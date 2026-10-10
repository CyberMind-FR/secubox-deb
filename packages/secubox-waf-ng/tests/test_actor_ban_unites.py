# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Bans automatiques (#2238, décision du propriétaire du 2026-10-11) : acteurs suivis et campagnes en « auto », ban sur le leurre dans le dropin du leurre."""
import re
from pathlib import Path

SYS = Path(__file__).resolve().parents[1] / "systemd"


def test_le_waf_est_livre_avec_les_bans_automatiques_des_acteurs_et_des_campagnes():
    t = (SYS / "secubox-waf-ng.service").read_text()
    assert re.search(r"^\s+--actor-ban auto", t, re.M)
    assert re.search(r"^\s+--campagne-ban auto", t, re.M)


def test_le_ban_sur_le_leurre_n_existe_que_dans_le_dropin_du_leurre():
    sans_commentaires = lambda txt: "\n".join(l for l in txt.splitlines() if not l.lstrip().startswith("#"))
    t = sans_commentaires((SYS / "secubox-waf-ng.service").read_text())
    d = sans_commentaires((SYS.parent / "conf" / "honeypot.conf").read_text())
    assert "--leurre-ban" in d and "--honeypot" in d and "--leurre-ban" not in t


def test_actord_publie_ses_propositions_ou_le_waf_les_lit():
    a = (SYS / "secubox-actord.service").read_text()
    w = (SYS / "secubox-waf-ng.service").read_text()
    chemin = re.search(r"--propositions (\S+)", a).group(1)
    assert chemin == "/run/secubox/actord-propositions.json"
    assert "actor-propositions" not in w or chemin in w   # le défaut de sbxwaf est ce même chemin


def test_les_adresses_de_la_box_sont_protegees():
    w = (SYS / "secubox-waf-ng.service").read_text()
    assert "--actor-ban-protegees" in w and "82.67.100.75" in w


def test_le_kill_switch_logique_est_livre_en_auto_dans_l_unite_et_le_dropin():
    """#2240 phase 4 : la réévaluation à l'échéance est active partout où les bans automatiques le sont."""
    for chemin in (SYS / "secubox-waf-ng.service", SYS.parent / "conf" / "honeypot.conf"):
        assert re.search(r"^\s+--reevaluation auto", chemin.read_text(), re.M), chemin


def test_actord_publie_ses_mesures_ou_sbxwaf_les_lit_et_l_echelle_est_livree_en_auto():
    """#2274 : l'échelle de réponse (délai, défi, tarpit, ban) est appliquée — actord publie, sbxwaf lit le même fichier, unité et dropin en `auto`."""
    a = (SYS / "secubox-actord.service").read_text()
    w = (SYS / "secubox-waf-ng.service").read_text()
    d = (SYS.parent / "conf" / "honeypot.conf").read_text()
    chemin = re.search(r"--mesures (\S+)", a).group(1)
    assert chemin == "/run/secubox/actord-mesures.json"
    for texte in (w, d):
        assert re.search(r"^\s+--mesures auto", texte, re.M)
    main_go = (SYS.parents[1] / "secubox-toolbox-ng" / "cmd" / "sbxwaf" / "main.go").read_text()
    assert re.search(r'"mesures-fichier", "([^"]+)"', main_go).group(1) == chemin       # le défaut de sbxwaf est ce même chemin
