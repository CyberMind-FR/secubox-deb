# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""« Demandes en attente » montre aussi les demandes reçues des autres box (#1895)."""
from pathlib import Path

PAGE = (Path(__file__).parent.parent / "www" / "assist" / "index.html").read_text()


def test_carte_en_attente_liste_les_demandes_recues():
    assert "renderPending(document.getElementById('log'), d.pending, recues)" in PAGE
    assert "q => !q.de_moi" in PAGE                      # pas les siennes : on répond aux autres
    assert "['reçue de', q.noeud" in PAGE


def test_bouton_repondre_sur_la_demande_recue():
    assert "act: 'request-answer'" in PAGE


def test_aucune_demande_seulement_si_les_deux_listes_sont_vides():
    assert "if (!mes.length && !autres.length)" in PAGE


def test_les_fonctions_asynchrones_gardent_leur_async():
    # Un découpage maladroit avait retiré `async` devant refreshOffers (await hors fonction async).
    import re
    for m in re.finditer(r"function (\w+)\([^)]*\) \{(.*?)\n\}\n", PAGE, re.S):
        if "await " in m.group(2):
            assert re.search(r"async function " + m.group(1) + r"\(", PAGE), m.group(1)
