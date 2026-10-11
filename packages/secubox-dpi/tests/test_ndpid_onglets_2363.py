# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2363 — les onglets du webui ndpid sont des pages autonomes du profil Aurora, encadrées."""
import pathlib

W = pathlib.Path(__file__).resolve().parents[1] / "composants/ndpid/www/ndpid"
INDEX = (W / "index.html").read_text(encoding="utf-8")
PAGES = {"flows": "flux", "protocols": "protocoles", "fingerprints": "empreintes", "risks": "risques", "settings": "reglages"}


def test_chaque_onglet_a_sa_page():
    for onglet, page in PAGES.items():
        assert f"{onglet}: '{page}'" in INDEX, onglet
        assert (W / f"{page}.html").is_file(), page


def test_l_ecouteur_de_hauteur_est_present():
    assert "e.data.sbxNdpidVue" in INDEX and "f.dataset.p === e.data.onglet" in INDEX


def test_seule_la_page_reglages_ecrit():
    for page in PAGES.values():
        src = (W / f"{page}.html").read_text(encoding="utf-8")
        ecrit = "method:'POST'" in src or 'method:"POST"' in src or "method: 'POST'" in src or "'POST'" in src
        assert ecrit == (page == "reglages"), page
