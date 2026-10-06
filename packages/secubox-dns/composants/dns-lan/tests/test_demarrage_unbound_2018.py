# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2018 : au démarrage de gk2, ~250 unités démarrent ensemble et Unbound dépassait les 90 s de
TimeoutStartSec : systemd le tuait puis le relançait, le DNS du LAN restait coupé ~4 min. Le paquet
pose un drop-in qui donne à Unbound le temps de charger ses listes."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
DROPIN = PAQUET / "conf" / "unbound-demarrage.conf"


def test_dropin_demarrage_unbound_a_un_delai_assez_long():
    texte = DROPIN.read_text()
    assert "[Service]" in texte
    delai = int(re.search(r"^TimeoutStartSec=(\d+)$", texte, re.M).group(1))
    assert delai >= 300          # 90 s par défaut ne suffisent pas sous la charge du démarrage


def test_dropin_est_installe_par_le_paquet():
    # dns-lan est un composant de secubox-dns depuis #2050 : l'installation vit dans les rules de l'absorbant
    rules = (PAQUET.parents[1] / "debian" / "rules").read_text()
    assert "unbound.service.d/10-secubox-demarrage.conf" in rules
