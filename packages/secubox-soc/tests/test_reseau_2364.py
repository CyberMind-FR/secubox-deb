# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2364 — les statistiques réseau live (débit par interface, paquets écartés) sont en première ligne du SOC."""
import pathlib

W = pathlib.Path(__file__).resolve().parents[1] / "www/soc"
PAGE = (W / "reseau.html").read_text(encoding="utf-8")
SOC = (W / "index.html").read_text(encoding="utf-8")


def test_la_page_lit_les_deux_routes_du_hub():
    assert "/api/v1/hub" in PAGE and "/netstats/summary" in PAGE and "/netstats/series?window=86400&step=300" in PAGE


def test_lecture_seule_et_sans_ressource_externe():
    assert "<script src=" not in PAGE and "POST" not in PAGE
    assert "lorem" not in PAGE.lower() and "SPDX-License-Identifier" in PAGE


def test_demo_annoncee_et_hauteur_postee():
    assert "?demo=1" in PAGE or "has('demo')" in PAGE
    assert "sbxVue" in PAGE and "min-height:100vh" not in PAGE


def test_l_onglet_est_juste_apres_guardian():
    i0, i1 = SOC.index('id="t0"'), SOC.index('id="tn"')
    assert i0 < i1 < SOC.index('id="tm"'), "Réseau en direct vient avant le groupe Pare-feu"
    assert 'data-vue="reseau.html?embed=1"' in SOC
