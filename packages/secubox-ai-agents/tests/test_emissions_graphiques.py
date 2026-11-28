# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 8 (#4058) : graphiques des dossiers, sans adresse, et association des diapositives."""
import ipaddress
import re
import shutil

import pytest

from emissions.graphiques import associer, graphiques, png

DOSSIER = {
    "sujet": {"genre": "campagne", "id": "c1", "nom": "Balayage 203.0.113.9"},
    "chiffres": {"bans_90j": 1204},
    "serie_semaine": [{"debut": "2026-09-01", "bans": 300}, {"debut": "2026-09-08", "bans": 904},
                      {"debut": "2026-09-15", "bans": 0}],
    "vagues": [{"debut": "2026-09-08", "fin": "2026-09-12", "bans": 904, "adresses": 77, "blocs24": 12,
                "jours_actifs": 5, "operateurs": ["OVH", "2001:db8::1"]}],
    "phases": [{"phase": "reconnaissance", "bans": 300}, {"phase": "exploitation", "bans": 904}],
    "operateurs": [{"nom": "OVH", "part": 61}, {"nom": "gk2.lan", "part": 9}],
}


def _adresses(texte):
    trouve = []
    for m in re.findall(r"[0-9A-Fa-f:.]{7,}", texte):
        try:
            ipaddress.ip_address(m.strip(".:"))
            trouve.append(m)
        except ValueError:
            pass
    return trouve


def test_aucune_adresse_dans_svg():
    gs = graphiques(DOSSIER)
    assert {g["id"] for g in gs} >= {"bans", "vague-1", "phases", "operateurs"}
    for g in gs:
        assert _adresses(g["svg"]) == [], g["id"]
        assert "gk2" not in g["svg"]
        assert not any(_adresses(t) for t in g["termes"])


def test_associer_par_chiffre():
    gs = graphiques(DOSSIER)
    rep = [{"rang": 0, "texte": "Bonjour à tous."},
           {"rang": 1, "texte": "La campagne totalise 1 204 bans."},
           {"rang": 2, "texte": "Et ensuite ?"},
           {"rang": 3, "texte": "Côté opérateurs, OVH domine."}]
    a = associer(rep, gs)
    g1204 = next(g["id"] for g in gs if "1204" in g["chiffres"])
    assert a[1] == g1204
    assert a[2] == a[1]                      # sans ancrage : la diapo précédente
    assert a[3] == "operateurs"


@pytest.mark.skipif(not shutil.which("rsvg-convert"), reason="rsvg-convert absent de ce poste")
def test_png(tmp_path):
    p = png(graphiques(DOSSIER)[0]["svg"], tmp_path / "g.png")
    assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
