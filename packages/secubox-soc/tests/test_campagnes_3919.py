# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3919 : Guardian a un bloc compact « Campagnes en cours » (4 lignes au plus), tout entier lien vers /waf/campagnes.html ;
aucune carte ni panneau du WAF (#3922). Le rendu partagé est essayé sous node dans secubox-waf-ng (cartes_campagnes_3919.test.mjs)."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "soc"
G = (WWW / "guardian.html").read_text(encoding="utf-8")


def _pop(n, **extra):
    return {"famille": "collecte", "cibles": [f"h{n}.example.test"], "adresses": 1000 + n, "reseaux": 3, "une": 90, "le3": 95, "classes": {"proxy_loue": 100}, "pays_top": [["US", 100]],
            "reseaux_top": [{"asn": 64500, "org": "Réseau exemple", "classe": "proxy_loue", "adresses": 9}], "serie": [0, 0, 0, 0, 0, 1, n], "bans": 2, "rotation": True, "etat": "bannie", **extra}


def _releve(pops, **extra):
    return {"disponible": True, "complet": True, "genere_le": 1764000000, "age_s": 4, "populations": pops, **extra}


def test_bloc_entier_lien_vers_le_waf():
    m = re.search(r'<a class="pan[^"]*" [^>]*href="/waf/campagnes\.html"[^>]*>(.*?)</a>', G, re.S)
    assert m and 'target="_top"' in m.group(0) and "Campagnes en cours" in m.group(1) and 'id="campagnes"' in m.group(1)
    assert "<a " not in m.group(1)


def test_scripts_relatifs_seulement():
    assert re.findall(r'<script src="([^"]+)"', G) == ["reperes.js", "cartes-campagnes.js"]
    for page in ("index", "defense", "reseau"):
        assert "<script src=" not in (WWW / f"{page}.html").read_text(encoding="utf-8"), page


def test_ni_carte_ni_copie_du_waf():
    assert "SbxCartes.populations" not in G and ".popc" not in G and "popdet" not in G and ".synthese(" in G
    bloc = G[G.index("// ---- Campagnes en cours (#3919)"):G.index("// ---- Fin des campagnes")]
    assert "innerHTML" not in bloc and "/api/v1/waf/populations" in bloc


@pytest.fixture(scope="module")
def nav():
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as e:
            pytest.skip(f"chromium indisponible : {e}")
        yield b
        b.close()


def _ouvre(nav, reponses, suffixe="", largeur=1280, sans_scripts=False):
    p = nav.new_context(viewport={"width": largeur, "height": 800}).new_page()
    p.erreurs, p.appels = [], []
    p.on("pageerror", lambda e: p.erreurs.append(str(e)))

    def servir(r):
        u = r.request.url.split("?")[0].split("g.test")[1]
        p.appels.append(u)
        if u.startswith("/api/"):
            c = reponses.get(u)
            return r.fulfill(status=200 if c is not None else 403, content_type="application/json", body=json.dumps(c if c is not None else {}))
        f = WWW / u[len("/soc/"):]
        if u.startswith("/soc/") and f.is_file() and not (sans_scripts and u.endswith(".js")):
            return r.fulfill(status=200, content_type="text/javascript" if u.endswith(".js") else "text/html", body=f.read_text(encoding="utf-8"))
        return r.fulfill(status=404, body="")
    p.route("http://g.test/**", servir)
    p.goto("http://g.test/soc/guardian.html" + suffixe)
    p.wait_for_timeout(500)
    return p


STATS = {"total_threats": 10, "observed_threats": 1, "by_severity": {}, "by_category": {"robots": 10}}


def test_quatre_lignes_au_plus_et_cible_hostile_inerte(nav):
    pops = [_pop(i) for i in range(1, 6)] + [_pop(99, cibles=["<img src=x onerror=window.xss=1>"]), _pop(200, etat="inactive", cibles=["vieux.example.test"])]
    p = _ouvre(nav, {"/api/v1/waf/stats": STATS, "/api/v1/waf/populations": _releve(pops)})
    t = p.inner_text("#campagnes")
    assert p.locator("#campagnes .cligne").count() == 4 and "<img src=x onerror=window.xss=1>" in t and "vieux" not in t
    assert "🌀 rotation" in t and "🛑 bannie" in t and "et 2 autres" in t and p.locator("#campagnes .cligne svg").count() == 4
    assert p.evaluate("window.xss") is None and p.locator("#campagnes img, #campagnes table, #campagnes article").count() == 0 and not p.erreurs
    p.context.close()


def test_relevé_partiel_puis_refus_discret(nav):
    p = _ouvre(nav, {"/api/v1/waf/stats": STATS, "/api/v1/waf/populations": _releve([_pop(1)], complet=False)})
    assert "Relevé partiel (" in p.inner_text("#campagnes")
    p.context.close()
    p = _ouvre(nav, {"/api/v1/waf/stats": STATS})
    assert p.inner_text("#campagnes") == "Relevé indisponible" and not p.locator("#session").is_visible()
    assert p.appels.count("/api/v1/waf/populations") == 1 and not p.erreurs
    p.context.close()


def test_scripts_absents_la_page_tient(nav):
    p = _ouvre(nav, {"/api/v1/waf/stats": STATS}, sans_scripts=True)
    assert "Relevé indisponible" in p.inner_text("#campagnes") and p.locator("#tuiles .tuile").count() == 7 and not p.erreurs
    p.context.close()


@pytest.mark.parametrize("suffixe", ["?demo=1", "?demo=1&embed=1"])
def test_demo_400_px(nav, suffixe):
    p = _ouvre(nav, {}, suffixe, 400)
    assert p.locator("#campagnes .cligne").count() == 4 and p.evaluate("document.documentElement.scrollWidth") <= 400 and not p.erreurs
    assert not [a for a in p.appels if a.startswith("/api/")]
    p.context.close()
