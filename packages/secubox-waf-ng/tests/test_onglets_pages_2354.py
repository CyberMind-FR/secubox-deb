# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2354 — les six onglets de l'administration du WAF sont des pages autonomes du profil Aurora, encadrées comme la vue d'ensemble."""
import pathlib

W = pathlib.Path(__file__).resolve().parents[1] / "composants/waf/www/waf"
INDEX = (W / "index.html").read_text(encoding="utf-8")
PAGES = {"overview": "menaces", "attackers": "attaquants", "visits": "visites", "recon": "surfaces", "history": "historique", "campaigns": "campagnes"}


def test_chaque_onglet_pointe_sa_page_et_la_page_existe():
    for onglet, page in PAGES.items():
        assert f"{onglet}: '{page}'" in INDEX, onglet
        assert (W / f"{page}.html").is_file(), page


def test_l_ecouteur_accepte_les_deux_cles_de_hauteur():
    assert "e.data.sbxwafVue" in INDEX and "e.data.sbxWafVue && e.data.onglet" in INDEX


def test_la_hauteur_de_la_vue_ne_depend_pas_de_la_hauteur_du_cadre():
    v = (W / "vue.html").read_text(encoding="utf-8")
    assert "sbxwafVue:document.documentElement.scrollHeight" not in v
    assert "container-name:a;min-height:100vh" not in v


def test_les_pages_sont_en_lecture_seule():
    for page in PAGES.values():
        src = (W / f"{page}.html").read_text(encoding="utf-8")
        assert "method:'POST'" not in src and 'method:"POST"' not in src and "method: 'POST'" not in src, page
