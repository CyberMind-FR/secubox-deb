# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 (projet 2) — rubrique « Pairs » du Hall v2 : les services publics des autres nœuds, lus par
`/api/v1/webos/public/pairs`. Tout texte vient d'un autre nœud : posé en texte, jamais en HTML ; un lien n'est posé
que sur une adresse https://."""
import json
import mimetypes
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")

PAIRS = {"pairs": [
    {"did": "did:plc:aaa", "boxname": "alpha", "domaine": "alpha.exemple.test", "mesh_ip": "10.8.0.2", "services": [
        {"nom": "Forum", "endpoint": "https://forum.alpha.exemple.test/", "description": "Le forum"},
        {"nom": "<img src=x onerror=window.PWNED=1>", "endpoint": "https://x.alpha.exemple.test/", "description": ""},
        {"nom": "Piégé", "endpoint": "javascript:window.PWNED=1", "description": ""},
    ]},
    {"did": "did:plc:bbb", "boxname": "beta", "domaine": "beta.exemple.test", "mesh_ip": "10.8.0.3", "services": [
        {"nom": "Radio", "endpoint": "https://radio.beta.exemple.test/", "description": ""},
    ]},
], "genere": "2026-10-24T10:00:00+00:00", "disponible": True}


def _bloc_pairs() -> str:
    d, f = JS.index("// >>> Pairs"), JS.index("// <<< Pairs")
    return JS[d:f]


def test_source_rubrique_declaree_sans_innerhtml():
    assert "{id:'pairs',nom:'Pairs'" in JS and "function tuilePair(" in JS and "function chargePairs(" in JS
    bloc = _bloc_pairs()
    assert "innerHTML" not in bloc and "insertAdjacentHTML" not in bloc and "el(" not in bloc
    assert "indexOf('https://')" in bloc and "noopener noreferrer" in bloc


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, statut=200, corps=PAIRS):
    ctx = nav.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps({"services": [], "computed_at": time.time(), "intervalle_s": 15}))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.20.0-1", "en_ligne": true}')
        if u == "/api/v1/webos/public/pairs":
            return r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps if statut == 200 else {}))
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if u.startswith(("/cardlets/", "/guardian/", "/dpi-vue/", "/actor-intelligence/")):
            return r.fulfill(status=200, content_type="text/html", body="<p>x</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector(".sbx-side .sbx-rub[data-rub='pairs']", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    p.click(".sbx-side .sbx-rub[data-rub='pairs']")
    return ctx, p, erreurs


def test_les_services_des_pairs_sont_des_liens_https_en_texte(nav):
    ctx, p, erreurs = ouvre(nav)
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-mosaique[data-vue='pairs'] .sbx-ptuile", state="attached")
    assert p.inner_text("#view-mosaique .sbx-mosaique-titre") == "Pairs"
    t = p.evaluate("[...document.querySelectorAll('.sbx-mosaique .sbx-ptuile')].map(e=>[e.tagName,e.getAttribute('href'),e.getAttribute('target'),e.getAttribute('rel'),e.querySelector('b').textContent,e.querySelector('small').textContent])")
    assert len(t) == 3, t                                   # le lien javascript: est écarté
    assert t[0] == ["A", "https://forum.alpha.exemple.test/", "_blank", "noopener noreferrer", "Forum", "alpha"]
    assert t[1][4] == "<img src=x onerror=window.PWNED=1>" and t[1][1].startswith("https://")
    assert t[2][4:] == ["Radio", "beta"]
    assert [x for x in p.evaluate("[...document.querySelectorAll('.sbx-pgroupe')].map(e=>e.textContent)")] == ["alpha", "beta"]
    assert p.evaluate("document.querySelectorAll('.sbx-mosaique img').length") == 0
    assert p.evaluate("typeof window.PWNED") == "undefined"
    assert "3 services" in p.inner_text("#view-mosaique .sbx-mosaique-compte")
    assert erreurs == []
    ctx.close()


def test_cache_indisponible_le_dit(nav):
    ctx, p, erreurs = ouvre(nav, corps={"pairs": [], "genere": None, "disponible": False})
    p.wait_for_selector("#view-mosaique .sbx-mosaique-vide:not([hidden])", state="attached")
    assert "Aucun autre nœud ne publie de service pour l’instant" in p.inner_text("#view-mosaique .sbx-mosaique-vide")
    assert p.evaluate("document.querySelectorAll('.sbx-mosaique .sbx-ptuile').length") == 0
    assert erreurs == []
    ctx.close()


def test_sans_session_la_mosaique_le_dit(nav):
    ctx, p, erreurs = ouvre(nav, statut=401)
    p.wait_for_selector("#view-mosaique .sbx-mosaique-vide:not([hidden])", state="attached")
    assert "session" in p.inner_text("#view-mosaique .sbx-mosaique-vide")
    assert p.evaluate("document.querySelectorAll('.sbx-mosaique .sbx-ptuile').length") == 0
    assert erreurs == []
    ctx.close()
