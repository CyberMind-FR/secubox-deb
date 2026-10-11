# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet Clients du Toolbox (profil Aurora) : garde-fous statiques, sans navigateur (ref #2373)."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "www" / "toolbox" / "clients.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC


def test_contrat_cadre():
    assert "sbxToolboxVue" in SRC
    assert "onglet:'clients'" in SRC
    assert "demo" in SRC and "embed" in SRC
    assert "100vh" not in SRC


def test_pas_de_script_externe():
    assert not re.search(r"<script[^>]+src=", SRC, re.I)
    assert not re.search(r"https?://(?!www\.w3\.org)", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))


def test_pas_de_lorem_ni_secret():
    low = SRC.lower()
    assert "lorem" not in low
    assert "privatekey" not in low and "private_key" not in low and "presharedkey" not in low


def test_pas_de_dialogue_natif():
    assert not re.search(r"(?<![\w.])confirm\(", SRC)
    assert not re.search(r"(?<![\w.])alert\(", SRC)


def test_routes_lecture():
    assert "/api/v1/toolbox" in SRC
    assert "/admin/clients/rich" in SRC
    assert "/admin/metrics" in SRC
    assert "'/events'" in SRC or "/events'" in SRC


def test_routes_ecriture_identiques_a_l_ancien_onglet():
    # niveau : POST FormData champ « level », credentials same-origin
    assert "fd.append('level',l)" in SRC
    assert "'/admin/clients/'+h+'/level',{method:'POST',body:fd,credentials:'same-origin'}" in SRC
    assert "'/admin/clients/'+h+'/reset',{method:'POST',credentials:'same-origin'}" in SRC
    assert "'/admin/clients/reset-all',{method:'POST',credentials:'same-origin'}" in SRC
    for lvl in ("r0", "r1", "r2", "r3"):
        assert f"{lvl}:[" in SRC
    # liens conservés
    assert "'/social'" in SRC and "'/report'" in SRC


def test_ancien_onglet_toujours_coherent():
    old = (PAGE.parent / "index.html").read_text(encoding="utf-8")
    for r in ("/admin/clients/${macHash}/level", "/admin/clients/${macHash}/reset", "/admin/clients/reset-all"):
        assert r in old or "clients/reset-all" in old


def test_oublier_des_clients_est_branche_et_confirme_dans_la_page_2379():
    """#2379 — la RAZ garde les lignes ; « oublier » les retire : appels, corps et confirmation intégrée."""
    assert "/admin/clients/forget" in SRC and "inactive_days" in SRC
    assert "'/forget'" in SRC or "/forget'" in SRC
    for ident in ("oublieInact", "oublieTous", "confOubli", "data-oubli", "data-oublioui"):
        assert ident in SRC, ident
    assert "confirm(" not in SRC and "alert(" not in SRC
