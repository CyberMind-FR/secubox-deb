# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Onglet Pubs du Toolbox au profil Aurora (ref #2373) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "www" / "toolbox" / "pubs.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx_et_cadre():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "sbxToolboxVue" in SRC and "onglet:'pubs'" in SRC
    assert "demo" in SRC and "embed" in SRC


def test_aucune_ressource_externe_ni_dialogue():
    assert not re.search(r"<script[^>]+src=", SRC)
    assert not re.search(r"https?://", re.sub(r"<!--.*?-->", "", SRC, flags=re.S).replace("http://www.w3.org", ""))
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()


def test_pas_de_secret():
    assert not re.search(r"(?i)(password|passwd|private_key|BEGIN [A-Z ]*KEY)", SRC)


def test_routes_lues():
    for r in ("/admin/ad-stats?hours=", "/admin/ad-stats/client/", "/admin/filters"):
        assert r in SRC
    assert "'/api/v1/toolbox'" in SRC


def test_action_ad_guard_identique():
    # même appel que l'ancien onglet : POST /admin/filters {ad_guard: !on}
    assert "API+'/admin/filters',{method:'POST'" in SRC
    assert "'content-type':'application/json'" in SRC
    assert "credentials:'same-origin'" in SRC
    assert "JSON.stringify({ad_guard:!on})" in SRC


def test_aucun_ecriture_en_demo():
    assert "DEMO_ON" in SRC and "if(!F||DEMO_ON) return;" in SRC


def test_listes_apprises_jamais_videes():
    assert "method:'DELETE'" not in SRC
    for r in ("splice-whitelist", "filter-control", "reset-all"):
        assert r not in SRC
