# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3672 : sur écran tactile, la barre d'icônes est STABLE — l'icône touchée reste à la même place quand le menu se
déplie, aucune animation, aucun repli automatique ; elle se referme en touchant ailleurs. Vrai navigateur, API simulée."""
import pytest

from tests.test_sidebar_espaces_2212 import MENU, SIDEBAR, navigateur  # noqa: F401 (fixture)

playwright = pytest.importorskip("playwright.sync_api")

PAGE_CSS = ("<!doctype html><html><head><meta charset=utf-8><title>t</title><link rel=stylesheet href='/shared/sidebar.css'></head>"
            "<body><nav class='sidebar' id='sidebar'></nav><main style='margin-left:220px'>contenu</main>"
            "<script src='/shared/sidebar.js'></script></body></html>")

TACTILE = """
const vrai = window.matchMedia.bind(window);
window.matchMedia = (q) => (q.includes('hover: none') ? {matches: true, media: q, addListener() {}, removeListener() {},
  addEventListener() {}, removeEventListener() {}} : vrai(q));
"""


def _ouvre(navigateur, tactile):  # noqa: F811
    import json
    ctx = navigateur.new_context(viewport={"width": 1024, "height": 768}, has_touch=tactile)
    p = ctx.new_page()
    if tactile:
        p.add_init_script(TACTILE)
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route("http://sbx.test/api/**", lambda r: r.fulfill(status=200, content_type="application/json",
                                                          body=json.dumps(MENU if r.request.url.endswith("/public/menu") else {})))
    css = SIDEBAR.with_name("sidebar.css").read_text(encoding="utf-8")
    p.route("http://sbx.test/shared/sidebar.css", lambda r: r.fulfill(status=200, content_type="text/css", body=css))
    p.route("http://sbx.test/shared/sidebar.js", lambda r: r.fulfill(status=200, content_type="application/javascript",
                                                                     body=SIDEBAR.read_text(encoding="utf-8")))
    p.route(lambda u: u.split("?")[0] == "http://sbx.test/waf/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE_CSS))
    p.goto("http://sbx.test/waf/")
    p.wait_for_function("document.querySelectorAll('#sidebar .nav-item').length >= 4", timeout=15000)
    p.wait_for_timeout(500)
    return ctx, p


def _icone_x(p):
    return p.evaluate("document.querySelector('#sidebar .nav-item .icon').getBoundingClientRect().left")


def test_tactile_icone_immobile_sans_animation_ni_repli(navigateur):  # noqa: F811
    ctx, p = _ouvre(navigateur, True)
    try:
        assert p.evaluate("document.documentElement.classList.contains('sbx-tactile')")
        assert p.evaluate("getComputedStyle(document.getElementById('sidebar')).transitionDuration") in ("0s", "0s, 0s")
        avant = _icone_x(p)
        p.evaluate("document.querySelector('#sidebar .nav-item').click()")      # premier appui : déplie, ne suit pas le lien
        assert p.evaluate("document.getElementById('sidebar').classList.contains('rail-ouvert')")
        assert p.url == "http://sbx.test/waf/"
        assert abs(_icone_x(p) - avant) < 1                                      # l'icône n'a pas bougé
        p.wait_for_timeout(5000)                                                 # au-delà de l'ancien repli (4 s)
        assert p.evaluate("document.getElementById('sidebar').classList.contains('rail-ouvert')")
        p.evaluate("document.querySelector('main').click()")                    # toucher ailleurs : repli
        assert not p.evaluate("document.getElementById('sidebar').classList.contains('rail-ouvert')")
    finally:
        ctx.close()


def test_souris_inchangee(navigateur):  # noqa: F811
    ctx, p = _ouvre(navigateur, False)
    try:
        assert not p.evaluate("document.documentElement.classList.contains('sbx-tactile')")
        assert p.evaluate("getComputedStyle(document.getElementById('sidebar')).transitionDuration") not in ("0s",)
    finally:
        ctx.close()
