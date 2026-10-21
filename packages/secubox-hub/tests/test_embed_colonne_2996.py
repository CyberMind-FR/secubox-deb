# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — encadrée par le Hall (sans ?embed=1), une page de module perd sa colonne de gauche : sidebar.js pose
`body.emb` (la convention des pages) et sidebar.css neutralise `.principal` / `.page` sous :root.sbx-embed."""
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
SHARED = Path(__file__).resolve().parents[1] / "www" / "shared"
JS = (SHARED / "sidebar.js").read_text(encoding="utf-8")
CSS = (SHARED / "sidebar.css").read_text(encoding="utf-8")
PAGE = ("<!doctype html><html><head><meta charset=utf-8><title>t</title><link rel=stylesheet href='/shared/sidebar.css'>"
        "<style>body:not(.emb) .principal{margin-left:220px} .principal{min-height:50px}</style></head>"
        "<body><nav class='sidebar' id='sidebar'></nav><main class='principal' id='p'>contenu</main><script src='/shared/sidebar.js'></script></body></html>")
CADRE = "<!doctype html><html><body style='margin:0'><iframe id='f' src='/page' style='width:900px;height:400px;border:0'></iframe></body></html>"


def test_source_pose_emb_et_la_feuille_neutralise_principal():
    assert "document.body.classList.add('emb')" in JS
    assert ":root.sbx-embed .principal" in CSS and ":root.sbx-embed .page" in CSS


def test_encadree_sans_parametre_la_colonne_disparait():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        p = b.new_page(viewport={"width": 1000, "height": 500})
        erreurs = []
        p.on("pageerror", lambda e: erreurs.append(str(e)))

        def sert(r):
            u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
            if u == "/cadre":
                return r.fulfill(status=200, content_type="text/html", body=CADRE)
            if u == "/page":
                return r.fulfill(status=200, content_type="text/html", body=PAGE)
            if u == "/shared/sidebar.js":
                return r.fulfill(status=200, content_type="application/javascript", body=JS)
            if u == "/shared/sidebar.css":
                return r.fulfill(status=200, content_type="text/css", body=CSS)
            if u.startswith("/shared/"):
                return r.fulfill(status=200, content_type="text/css", body="")
            r.fulfill(status=404, content_type="application/json", body="{}")
        p.route("http://sbx.test/**", sert)
        # en accès direct : la colonne de la barre est là
        p.goto("http://sbx.test/page")
        p.wait_for_selector("#p")
        assert p.evaluate("getComputedStyle(document.getElementById('p')).marginLeft") == "220px"
        assert not p.evaluate("document.body.classList.contains('emb')")
        # encadrée (window.top !== window.self), sans ?embed=1 : plus de colonne
        p.goto("http://sbx.test/cadre")
        cadre = p.frame(name=None, url="http://sbx.test/page") or [f for f in p.frames if f.url.endswith("/page")][0]
        cadre.wait_for_selector("#p")
        cadre.wait_for_function("document.body.classList.contains('emb')")
        assert cadre.evaluate("document.documentElement.classList.contains('sbx-embed')")
        assert cadre.evaluate("getComputedStyle(document.getElementById('p')).marginLeft") == "0px"
        assert erreurs == []
        b.close()
