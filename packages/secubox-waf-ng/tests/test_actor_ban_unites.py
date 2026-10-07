# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le ban automatique d'Actor Intelligence est LIVRÉ en mode « propose » : rien ne s'applique tant que l'opérateur n'a pas passé « auto »."""
import re
from pathlib import Path

SYS = Path(__file__).resolve().parents[1] / "systemd"


def test_le_waf_est_livre_en_mode_propose_pas_auto():
    t = (SYS / "secubox-waf-ng.service").read_text()
    m = re.search(r"^\s+--actor-ban (\S+)", t, re.M)
    assert m and m.group(1) == "propose"


def test_actord_publie_ses_propositions_ou_le_waf_les_lit():
    a = (SYS / "secubox-actord.service").read_text()
    w = (SYS / "secubox-waf-ng.service").read_text()
    chemin = re.search(r"--propositions (\S+)", a).group(1)
    assert chemin == "/run/secubox/actord-propositions.json"
    assert "actor-propositions" not in w or chemin in w   # le défaut de sbxwaf est ce même chemin


def test_les_adresses_de_la_box_sont_protegees():
    w = (SYS / "secubox-waf-ng.service").read_text()
    assert "--actor-ban-protegees" in w and "82.67.100.75" in w
