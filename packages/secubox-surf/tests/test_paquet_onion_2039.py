# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2039 — le surfer doit pouvoir sortir par Tor sur n'importe quelle box.

Sur gk3, tout .onion répondait HTTP 500 : « Using SOCKS proxy, but the 'socksio' package is not installed ».
La dépendance `python3-socksio | python3-pip` était satisfaite par pip, donc socksio n'était jamais installé.
Et l'unité figeait l'adresse Tor de gk2 (192.168.1.200:9050) : sur une autre machine, le surfer aurait
emprunté le Tor d'une box voisine. Le code détecte déjà le SOCKS local (egress._resout_tor_socks)."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]


def test_socksio_est_une_dependance_ferme():
    controle = (PAQUET / "debian" / "control").read_text()
    depends = re.search(r"(?ms)^Depends:(.*?)^\S", controle).group(1)
    # python3-socksio ne doit pas être une simple alternative à pip
    assert re.search(r"python3-socksio\s*(,|$)", depends.replace("\n", " ")), depends
    assert "python3-socksio | python3-pip" not in depends


def test_l_unite_ne_fige_pas_le_tor_d_une_autre_machine():
    unite = (PAQUET / "systemd" / "secubox-surf.service").read_text()
    assert not re.search(r"(?m)^Environment=.*SECUBOX_TOR_SOCKS=\d+\.\d+\.\d+\.\d+", unite)
    assert "192.168." not in unite
