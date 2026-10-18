# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2917 — une minuterie « OnBootSec + OnUnitActiveSec » ne se redeclenche pas quand elle est reactivee apres le demarrage.

gk2 : le collecteur netstats n'a collecte qu'une fois, au demarrage du 14/10 ; l'onglet Temps reel
affichait DONNEES PERIMEES. `OnActiveSec` compte depuis l'activation de la minuterie : il la relance a chaque (re)demarrage."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
MINUTERIES = ["secubox-hub/debian/secubox-netstats.timer",
              "secubox-annuaire/systemd/secubox-annuaire-apply.timer",
              "secubox-annuaire/systemd/secubox-annuaire-bans-apply.timer"]


def test_chaque_minuterie_a_un_declencheur_depuis_son_activation():
    for m in MINUTERIES:
        t = (PAQUETS / m).read_text()
        assert re.search(r"^OnActiveSec=\d+s?$", t, re.M), m
        assert re.search(r"^OnUnitActiveSec=\d+s?$", t, re.M), m
