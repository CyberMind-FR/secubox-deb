# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Graphiques du rapport : camembert des pays, courbe de cumul (#1190).

Fichier SEPARE parce que ces tests dependent de matplotlib, absent du poste de
developpement et present sur la box. Un `importorskip` au niveau module aurait
fait sauter, dans le fichier voisin, des tests qui n'ont rien a voir avec lui.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
pytest.importorskip("matplotlib")


# ── #1190 — camembert des pays et courbe de cumul ──────────────────────────
#
# Ces tests touchent le rendu matplotlib. Il n'est pas installe partout (le
# poste de developpement s'en passe, la box l'a) : on saute plutot que de
# rougir pour une dependance absente.
pytest.importorskip("matplotlib")

def test_camembert_regroupe_la_longue_traine():
    """Au-dela de sept parts un camembert ne se lit plus : les suivantes sont
    regroupees. Les montrer separement reviendrait a ne montrer personne."""
    import rapport
    pays = {f"P{i}": 100 - i for i in range(12)}
    png = rapport._camembert(pays)
    assert png[:8] == b"\x89PNG\r\n\x1a\n", "ce n'est pas un PNG"
    assert len(png) > 1000


def test_camembert_sans_donnees_ne_casse_pas():
    import rapport
    assert rapport._camembert({})[:8] == b"\x89PNG\r\n\x1a\n"


def test_le_cumul_part_de_l_acquis_pas_de_zero():
    """Sans la base, la courbe repartirait de zero tous les trente jours et ne
    dirait plus « depuis la premiere visite » mais « depuis un mois »."""
    import rapport
    serie = [{"jour": "2026-08-24", "visites": 10},
             {"jour": "2026-08-25", "visites": 5}]
    assert rapport._cumul(serie, base=500, depuis="2025-01-01")[:8] == b"\x89PNG\r\n\x1a\n"
    assert rapport._cumul([], base=0)[:8] == b"\x89PNG\r\n\x1a\n"


def test_pays_normalise_les_deux_formes():
    """L'API rend une liste d'entrees, le cumul rend un dict : le PDF doit
    accepter les deux sans que l'appelant ait a s'en soucier."""
    import rapport
    assert rapport._pays_de({"pays": {"FR": 3}}) == {"FR": 3}
    assert rapport._pays_de({"pays": [{"code": "FR", "n": 3}]}) == {"FR": 3}
    assert rapport._pays_de({}) == {}
