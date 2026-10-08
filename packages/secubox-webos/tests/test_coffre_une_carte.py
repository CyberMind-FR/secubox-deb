# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le Hall n'a qu'UNE carte « Coffre » (#2146).

« Coffre » (l'état de la box) et « Mon coffre » (le compartiment de la personne) étaient deux cartes qui disaient la même chose
côté état — scellé ou ouvert — et se doublaient pour un administrateur. Une seule reste : la page « Mon coffre », dont le badge dit
l'état du Coffre de la box ; la console d'administration (compteurs, journal, serrures) reste derrière le ⚙️."""
import json
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")
AIDE = json.loads((PKG / "api" / "aide_cartes.json").read_text(encoding="utf-8"))


def test_une_seule_carte_coffre_dans_le_hall():
    assert not re.search(r'\{id:"coffre"\s*,', HALL), "la carte d'état « Coffre » doublonnait « Mon coffre »"
    m = re.search(r'\{id:"mon-coffre",[^}]*\}', HALL)
    assert m, "la carte du compartiment reste"
    assert 'label:"Coffre"' in m.group(0)
    assert 'carte:"/coffre/"' in m.group(0)
    assert 'admin:"/vault/"' in m.group(0), "la console du Coffre reste atteignable (⚙️)"


def test_l_aide_ne_decrit_qu_une_carte_coffre():
    ids = [c["id"] for c in AIDE["cartes"] if c["id"] in ("coffre", "mon-coffre")]
    assert ids == ["mon-coffre"]
    c = next(c for c in AIDE["cartes"] if c["id"] == "mon-coffre")
    assert c["nom"] == "Coffre"
