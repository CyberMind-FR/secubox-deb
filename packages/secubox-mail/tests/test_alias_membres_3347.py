# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3347 — membres d'un alias : routes, liste des membres, page."""
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
CTL = (PKG / "sbin" / "mailctl").read_text(encoding="utf-8")
API = (PKG / "api" / "main.py").read_text(encoding="utf-8")
HTML = (PKG / "www" / "mail" / "index.html").read_text(encoding="utf-8")


def test_mailctl_verbes_membres():
    assert "membre-add)" in CTL and "alias_membre_add" in CTL
    assert "membre-del)" in CTL and "alias_membre_del" in CTL


def test_routes_membres_gardees():
    assert '@app.post("/alias/{alias_email}/membres", dependencies=[Depends(require_jwt)])' in API
    assert '@app.delete("/alias/{alias_email}/membres/{cible}", dependencies=[Depends(require_jwt)])' in API
    assert '"membre-add"' in API and '"membre-del"' in API


def test_liste_rend_les_membres():
    bloc = API.split("def membres_alias(", 1)[1].split("\n\n\n", 1)[0]
    ns = {}
    exec("import re\ndef membres_alias(" + bloc, ns)
    assert ns["membres_alias"]("contact@secubox.in gk2@secubox.in, cedre83@secubox.in") == \
        ("contact@secubox.in", ["gk2@secubox.in", "cedre83@secubox.in"])
    assert ns["membres_alias"]("a@b.c x@y.z") == ("a@b.c", ["x@y.z"])


def test_page_gere_les_membres_sans_innerhtml_de_donnees():
    assert "/membres" in HTML and "Ajouter un membre" in HTML and "Retirer" in HTML
    corps = HTML.split("Ajouter un membre", 1)[0][-4000:]
    assert ".innerHTML =" not in corps.split("function rendreAlias", 1)[-1]
