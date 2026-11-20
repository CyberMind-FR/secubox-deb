# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3839 — vue « Cyber Defense Live » : contrôles statiques sur le texte de la page et sur l'onglet du SOC."""
import pathlib
import re

W = pathlib.Path(__file__).resolve().parents[1] / "www/soc"
PAGE = (W / "defense.html").read_text(encoding="utf-8")
SOC = (W / "index.html").read_text(encoding="utf-8")


def test_entete_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in PAGE


def test_aucune_autre_origine_ni_bibliotheque():
    assert "<script src=" not in PAGE and "<link" not in PAGE and "@import" not in PAGE
    assert not re.search(r"https?://|//[a-z0-9.-]+\.[a-z]{2,}", PAGE.replace("</", "")), "aucune URL externe"


def test_les_sept_lectures_visent_la_facade():
    assert PAGE.count("fetch(") == 1 and "'/api/v1/soc/defense'" in PAGE
    for chemin in ("/status", "/threats", "/threats/", "/actions", "/mesh", "/incidents?jours=7", "/policies"):
        assert re.search(r"lire\('" + re.escape(chemin), PAGE), chemin


def test_lecture_seule_sans_ecriture():
    assert "POST" not in PAGE and "method" not in PAGE


def test_jeton_sous_la_cle_sbx_token():
    assert "localStorage.getItem('sbx_token')" in PAGE


def test_sections_presentes():
    for s in ("phases", "flux", "approbation", "incidents", "synthese", "maillage", "seuils"):
        assert f'id="{s}"' in PAGE, s


def test_modes_non_livres_desactives_avec_infobulle():
    for m in ("active", "aggressive"):
        b = re.search(r'<button[^>]*data-mode="' + m + r'"[^>]*>', PAGE)
        assert b and " disabled" in b.group(0) and "gestes gradués non livrés (V2 4-7)" in b.group(0), m
    for m in ("observe", "reactive"):
        b = re.search(r'<button[^>]*data-mode="' + m + r'"[^>]*>', PAGE)
        assert b and " disabled" not in b.group(0), m


def test_aucune_valeur_fictive_de_la_maquette():
    assert "203.0.113.45" not in PAGE and "198.51.100" not in PAGE and not re.search(r"\b82\b", PAGE)
    assert "Menaces (24 h)" not in PAGE and "Acteurs suivis" in PAGE and "Événements 24 h" in PAGE


def test_carte_d_approbation_vide_sans_bouton():
    m = re.search(r'<section[^>]*id="approbation".*?</section>', PAGE, re.S)
    assert m and "Aucune proposition chargée — la file s'ouvre en mode REACTIVE" in m.group(0)
    assert "<button" not in m.group(0) and "/proposals" not in PAGE


def test_etats_honnetes():
    assert "relevé indisponible" in PAGE and "échantillon des 7 derniers jours" in PAGE
    assert "score_max" in PAGE and "bande_max" in PAGE and "menaces_suivies" in PAGE and "evenements_24h" in PAGE


def test_rafraichissement_15s_suspendu_onglet_cache():
    assert "15000" in PAGE and "document.hidden" in PAGE and "sbxVue" in PAGE


def test_onglet_du_soc_en_tete():
    assert 'data-vue="defense.html?embed=1"' in SOC
    assert SOC.index('data-vue="defense.html?embed=1"') < SOC.index('id="t0"')


def test_incidents_signales_quand_le_waf_est_muet():
    f = re.search(r"function rendIncidents.*?\n  }\n", PAGE, re.S).group(0)
    assert "src(r, 'waf')" in f and "WAF indisponible : l\\'issue des incidents est inconnue" in f
    assert "issue inconnue" in f


def test_bandes_gardees_quand_la_base_est_indisponible():
    f = re.search(r"function rendSeuils.*?\n  }\n", PAGE, re.S).group(0)
    assert "etat_base === 'indisponible'" in f and "if (!r.ok || !r.d) {" in f
