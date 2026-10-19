# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2798 — page Flux : la rangee repartition / applications / hotes passe AU-DESSUS de la liste des flux actifs."""
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "flux.html").read_text(encoding="utf-8")


def test_la_rangee_de_synthese_precede_la_liste_des_flux():
    assert PAGE.index('<div class="grille g3">') < PAGE.index("<h3>Flux actifs")


def test_la_rangee_suit_les_tuiles_et_garde_ses_trois_panneaux():
    assert PAGE.index('id="tuiles"') < PAGE.index('<div class="grille g3">')
    bloc = PAGE.split('<div class="grille g3">', 1)[1].split("Lecture seule", 1)[0]
    for panneau in ("Répartition par protocole", "<h3>Applications", "Hôtes les plus actifs"):
        assert panneau in bloc
