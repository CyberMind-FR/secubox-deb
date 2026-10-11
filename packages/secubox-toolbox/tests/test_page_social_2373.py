# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet « Cartographie sociale » du Toolbox, refait au profil Aurora (#2373) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "toolbox" / "social.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_entete_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC


def test_contrat_avec_l_index_et_la_demo():
    assert "sbxToolboxVue" in SRC and "onglet:'social'" in SRC
    assert "demo" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC
    assert "embed" in SRC


def test_aucune_ressource_externe_ni_texte_factice():
    assert not re.search(r"<script[^>]+src=", SRC)
    assert not re.search(r"https?://(?!www\.w3\.org)", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))
    assert "lorem" not in SRC.lower()
    assert not re.search(r"(BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*['\"][^'\"]+)", SRC)


def test_pas_de_boites_du_navigateur():
    assert not re.search(r"(?<![\w.])(confirm|alert|prompt)\(", SRC)


def test_routes_lues_et_ecriture_a_l_identique():
    assert "/api/v1/toolbox" in SRC
    assert "/admin/social-aggregate?hours=24" in SRC
    assert "/admin/device-blocks?hours=24" in SRC
    # action de l'ancien onglet : POST /admin/quarantine/{ip}, sans corps
    assert "'/admin/quarantine/'+encodeURIComponent(ip)" in SRC
    assert "method:'POST'" in SRC
    assert "sbx_token" in SRC and "Bearer" in SRC and "credentials:'same-origin'" in SRC


def test_aucune_ecriture_en_demo_et_graphe_sans_librairie():
    assert "if(DEMOMODE){annonce" in SRC
    assert "<svg" in SRC and "d3" not in SRC
    assert "setInterval" in SRC and "12000" in SRC
