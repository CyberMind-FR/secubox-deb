# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2423 — la clé de jonction NAC ↔ Toolbox est un condensat stable de la MAC, identique des deux côtés."""
from api.clients_reels import cle_appareil


def test_cle_stable_et_independante_de_la_casse():
    assert cle_appareil("AA:BB:CC:DD:EE:01") == cle_appareil("aa:bb:cc:dd:ee:01")
    assert len(cle_appareil("aa:bb:cc:dd:ee:01")) == 12


def test_cle_figee_identique_a_celle_du_toolbox():
    # Même valeur figée dans packages/secubox-toolbox/tests/test_clients_appareils_2415.py : si l'une des deux dérivations change, un test casse.
    assert cle_appareil("aa:bb:cc:dd:ee:01") == "077a24919e64"


def test_la_mac_n_apparait_pas_dans_la_cle():
    c = cle_appareil("aa:bb:cc:dd:ee:01")
    assert "aa:bb" not in c and ":" not in c
