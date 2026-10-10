# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La carte du monde de la page Actor est une grille de 60 × 120 points de 3° (jeu TERRE, un run-length par ligne). La ligne 7 (≈ 67,5° N) était fautive :
une bande continue de 64 points traversait tout l'Atlantique Nord, de l'Alaska à la Norvège, et la Sibérie manquait."""
import re
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / "www" / "actor" / "index.html").read_text(encoding="utf-8")


def grille():
    brut = re.search(r'var TERRE="([^"]*)"', PAGE).group(1).split("|")
    lignes = []
    for r in brut:
        terre, ligne = r[0] == "1", []
        for n in r[1:].split(","):
            ligne += [terre] * int(n)
            terre = not terre
        lignes.append(ligne)
    return lignes


def test_la_grille_fait_60_lignes_de_120_points():
    g = grille()
    assert len(g) == 60 and all(len(l) == 120 for l in g)


def test_la_ligne_7_ne_traverse_plus_l_atlantique_nord():
    l = grille()[7]
    assert not any(l[51:64]), "entre le Groenland (x≤49) et la Norvège (x≥65) il n'y a que de l'océan à 67° N"
    assert all(l[42:50]), "le Groenland est de la terre"
    assert all(l[70:84]), "la Russie du Nord est de la terre (elle manquait)"
    assert all(l[10:30]), "le Canada arctique est de la terre"


def test_aucune_ligne_n_a_de_bande_continue_de_plus_de_80_points():
    """Le plus long continent d'une ligne (Eurasie) reste sous 80 points de 3° ; au-delà, c'est un défaut d'encodage."""
    for j, l in enumerate(grille()):
        plus, cur = 0, 0
        for v in l:
            cur = cur + 1 if v else 0
            plus = max(plus, cur)
        assert plus <= 80, f"ligne {j} : bande continue de {plus} points"
