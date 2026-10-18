# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2899 — netdiag absorbe Routes et SOC Reseau en onglets ; iperf3 est integre ; minimal l'embarque."""
import re
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
PAGE = (ICI / "composants/netdiag/www/netdiag/index.html").read_text()
CONTROL = (ICI / "debian/control").read_text()
PAQUETS = ICI.parent


def test_onglet_gestion_des_routes_en_iframe_embarquee():
    assert 'data-t="gestion"' in PAGE
    assert "/routes/?embed=1" in PAGE


def test_onglet_soc_reseau_seulement_si_la_page_existe():
    assert 'data-t="soc"' in PAGE and "/soc/reseau.html?embed=1" in PAGE
    assert re.search(r"HEAD[^;]*soc/reseau\.html|soc/reseau\.html[^;]*HEAD", PAGE), "sonde HEAD avant d'afficher l'onglet"
    assert 'id="o-soc" data-t="soc"' in PAGE and "hidden" in PAGE.split('id="o-soc"', 1)[1][:120]


def test_les_iframes_se_chargent_au_premier_affichage_seulement():
    assert "data-src" in PAGE, "pas de chargement de page tierce tant que l'onglet n'est pas ouvert"


def test_l_entree_de_menu_routes_est_retiree():
    assert not (ICI / "menu.d/907-routes.json").exists()


def test_iperf3_est_integre_pas_seulement_recommande():
    dep = CONTROL.split("Depends:", 1)[1].split("Recommends:", 1)[0]
    assert "iperf3" in dep


def test_minimal_embarque_routes_et_son_profil_les_active():
    ctrl = (PAQUETS / "secubox-minimal/debian/control").read_text()
    assert re.search(r"secubox-routes \(>= 1\.5\.0\)", ctrl)
    prof = (PAQUETS / "secubox-profiles/profiles/minimal.toml").read_text()
    assert '"netdiag"' in prof and '"routes"' in prof
