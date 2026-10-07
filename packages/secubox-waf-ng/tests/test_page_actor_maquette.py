# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Page Actor Intelligence (admin.gk2/actor/, actor.gk2) : vues de la maquette, données réelles seulement."""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "www" / "actor" / "index.html").read_text()


def test_vue_d_ensemble_tuiles_carte_et_evenements():
    for ident in ("tuiles", "carteMonde", "paysTop", "even"):
        assert f'id="{ident}"' in HTML, ident
    for fonction in ("function carteMonde(", "function rendEven(", "function rendTuiles(", "function aperçu("):
        assert fonction in HTML, fonction
    assert "/api/v1/actor/overview" in HTML


def test_la_fiche_a_la_courbe_24h_et_les_techniques():
    assert "function courbe(" in HTML and "activite_acteurs" in HTML
    assert "Techniques observées" in HTML and "techniques" in HTML


def test_les_tuiles_suivent_le_score_de_la_page():
    # critiques / suspects / observés : même échelle que palierScore() (70 / 45), jamais un second barème
    assert re.search(r"function rendTuiles\([^)]*\)\{[^}]*score\(", HTML, re.S)


def test_l_apercu_n_est_relu_qu_une_fois_par_minute():
    assert re.search(r"55000|60000", HTML)


def test_valeurs_serveur_echappees_et_aucune_ressource_externe():
    assert "esc(e.acteur" in HTML and "esc(e.type" in HTML and "esc(e.module" in HTML
    assert "http://" not in HTML.replace("http://www.w3.org/2000/svg", "")


def test_pas_de_donnees_inventees():
    assert "Math.random" not in HTML


def test_moteur_absent_ou_en_demarrage_est_dit_clairement():
    assert "en démarrage ou injoignable" in HTML and "nouvel essai automatique" in HTML
