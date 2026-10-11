# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#2373 : page « Filtres MITM » du Toolbox au profil Aurora (contrôles statiques)."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "www" / "toolbox" / "filtres.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx_et_vue():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "sbxToolboxVue" in SRC and "onglet:'filtres'" in SRC
    assert "demo" in SRC and "embed" in SRC


def test_autonome_sans_externe():
    assert not re.search(r"<script[^>]+src=", SRC)
    assert not re.search(r"https?://(?!www\.w3\.org)", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))


def test_pas_de_boites_natives_ni_lorem_ni_secret():
    assert not re.search(r"\b(confirm|alert|prompt)\(", SRC)
    low = SRC.lower()
    assert "lorem" not in low
    assert not re.search(r"BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]", SRC, re.I)


def test_routes_lecture():
    for r in ("/api/v1/toolbox", "/admin/filter-control/list",
              "/admin/splice-whitelist/list", "/admin/splice-whitelist/candidates"):
        assert r in SRC


def test_routes_ecriture_identiques():
    for r in ("/admin/filter-control/toggle", "/admin/filter-control/delete",
              "/admin/splice-whitelist/json-add", "/admin/splice-whitelist/json-remove",
              "/admin/splice-whitelist/promote", "/admin/splice-whitelist/ignore"):
        assert r in SRC
    assert "method:'POST'" in SRC and "JSON.stringify(body)" in SRC
    assert "{pattern:pattern}" in SRC and "{host:host}" in SRC and "{host:h}" in SRC


def test_aucune_ecriture_en_demo():
    assert "Démonstration : aucune écriture" in SRC
