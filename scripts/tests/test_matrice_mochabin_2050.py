# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Release : la MOCHAbin ne publie que lite et isp ; `full` (2,6 Go) dépasse les 2 Gio d'un fichier de release GitHub
et faisait échouer l'étape « Create GitHub Release » (alpha 9). Les autres cartes ne changent pas."""
import importlib.util
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
_s = importlib.util.spec_from_file_location("matrice", RACINE / ".github/scripts/matrice-images.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


def _profils(carte):
    return [x["profile"] for x in m.matrice(RACINE, [carte]) if x["board"] == carte]


def test_mochabin_publie_lite_et_isp_seulement():
    assert _profils("mochabin") == ["lite", "isp"]


def test_les_autres_cartes_sont_inchangees():
    assert _profils("rpi400") == ["full", "isp"]
    assert _profils("vm-x64") == ["full", "isp"]


def test_la_matrice_par_defaut_ne_contient_aucun_full_mochabin():
    toutes = m.matrice(RACINE, ["mochabin", "vm-x64", "rpi400", "espressobin-v7"])
    assert {"board": "mochabin", "profile": "full"} not in toutes


def test_l_espressobin_ne_publie_que_lite():
    """Depuis la refonte des profils (#2146), isp porte l'hebergement (8 Go) : jamais sur une carte de 1 a 2 Go."""
    assert _profils("espressobin-v7") == ["lite"]
    assert _profils("espressobin-ultra") == ["lite"]
