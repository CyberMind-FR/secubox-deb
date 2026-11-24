# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3919 — page Campagnes du WAF : section « Campagnes et populations » en tête, cartes partagées (cartes-campagnes.js),
relevé lu discrètement. Le rendu est essayé sous node (cartes_campagnes_3919.test.mjs), la page dans un navigateur."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

W = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf"
HTML = (W / "campagnes.html").read_text(encoding="utf-8")
JS = W / "cartes-campagnes.js"
TEST_MJS = Path(__file__).with_name("cartes_campagnes_3919.test.mjs")


def test_scripts_relatifs_avant_le_script_de_la_page():
    assert re.findall(r'<script src="([^"]+)"', HTML) == ["reperes.js", "cartes-campagnes.js"]
    assert HTML.index('src="cartes-campagnes.js"') < HTML.index("<script>")


def test_section_en_tete_et_contenu_existant_dessous():
    assert HTML.index("Campagnes et populations</h2>") < HTML.index("Campagnes d’attaque</h2>") < HTML.index('id="frise"') < HTML.index('id="cartes"')
    assert HTML.index('id="populations"') < HTML.index('id="tuiles"')


def test_cartes_partagees_sans_balisage_ni_style():
    js = JS.read_text(encoding="utf-8")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in js
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMParser", "fetch(", "cssText", "<style"):
        assert interdit not in js, interdit


def test_section_sans_innerhtml_et_route_lue():
    bloc = HTML[HTML.index("// ---- Populations (#3919)"):HTML.index("// ---- Fin des populations")]
    assert "innerHTML" not in bloc and "/api/v1/waf/populations" in bloc


def test_rendu_node():
    if not shutil.which("node"):
        pytest.skip("node absent")
    r = subprocess.run(["node", "--test", str(TEST_MJS)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]


HOSTILE = {"disponible": True, "complet": False, "genere_le": 1764000000, "age_s": 3, "populations": [
    {"famille": "collecte", "cibles": ["<img src=x onerror=window.xss=1>"], "adresses": 60, "reseaux": 2, "une": 90, "le3": 95, "classes": {"proxy_loue": 100},
     "pays_top": [["US", 100]], "reseaux_top": [{"asn": 64500, "org": "<img src=x onerror=window.xss=2>", "classe": "proxy_loue", "adresses": 60}],
     "serie": [0, 0, 0, 0, 0, 0, 60], "bans": 1, "rotation": True, "etat": "bannie"}]}


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


def _ouvre(nav, reponses, suffixe="", largeur=1280, chemin="/waf/"):
    p = nav.new_context(viewport={"width": largeur, "height": 800}).new_page()
    p.erreurs, p.appels = [], []
    p.on("pageerror", lambda e: p.erreurs.append(str(e)))

    def servir(r):
        u = r.request.url.split("?")[0].split("g.test")[1]
        p.appels.append(u)
        if u.startswith("/api/"):
            c = reponses.get(u)
            return r.fulfill(status=200 if c is not None else 401, content_type="application/json", body=json.dumps(c if c is not None else {}))
        f = W / u[len(chemin):]
        if u.startswith(chemin) and f.is_file():
            return r.fulfill(status=200, content_type="text/javascript" if u.endswith(".js") else "text/html", body=f.read_text(encoding="utf-8"),
                             headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"})
        return r.fulfill(status=404, body="")
    p.route("http://g.test/**", servir)
    p.goto("http://g.test" + chemin + "campagnes.html" + suffixe)
    p.wait_for_timeout(500)
    return p


@pytest.mark.parametrize("chemin", ["/waf/", "/"])
def test_navigateur_cible_hostile_inerte_et_partiel_date(nav, chemin):
    """Servie sous /waf/ (console) comme à la racine du vhost waf.*, avec la CSP du vhost."""
    p = _ouvre(nav, {"/api/v1/waf/populations": HOSTILE}, chemin=chemin)
    t = p.inner_text("#populations")
    assert "<img src=x onerror=window.xss=1>" in t and "Relevé partiel (" in t and "🛑 bannie" in t
    assert p.evaluate("window.xss") is None and p.locator("#populations img").count() == 0 and not p.erreurs
    p.context.close()


def test_navigateur_refus_discret(nav):
    """401 sur les populations seules : section indisponible, pas de bandeau de session, un seul appel."""
    p = _ouvre(nav, {"/api/v1/waf/campaigns": {"available": True, "attaquants": 0, "campagnes": []}, "/api/v1/waf/alerts": {"alerts": []}, "/api/v1/waf/bans": {"bans": []}})
    assert p.inner_text("#populations") == "Relevé indisponible" and not p.locator("#session").is_visible()
    assert p.appels.count("/api/v1/waf/populations") == 1 and not p.erreurs
    p.context.close()


@pytest.mark.parametrize("suffixe", ["?demo=1", "?demo=1&embed=1"])
def test_navigateur_demo_400_px_sans_debordement(nav, suffixe):
    p = _ouvre(nav, {}, suffixe, 400)
    assert p.locator("#populations article").count() >= 4 and p.locator("#demo").is_visible()
    assert p.evaluate("document.documentElement.scrollWidth") <= 400 and not p.erreurs
    p.evaluate("document.querySelectorAll('#populations details').forEach(function(d){d.open=true;})")
    assert p.evaluate("document.documentElement.scrollWidth") <= 400
    assert p.evaluate("[...document.querySelectorAll('#populations *')].filter(function(e){return e.scrollWidth>e.clientWidth+1&&/auto|scroll/.test(getComputedStyle(e).overflowX);}).length") == 0
    assert p.evaluate("[...document.querySelectorAll('#populations .puce')].every(function(e){var c=getComputedStyle(e);return c.whiteSpace==='normal'&&c.textOverflow!=='ellipsis'&&e.scrollWidth<=e.clientWidth+1;})")
    assert "/api/v1/waf/populations" not in p.appels
    p.context.close()


def test_hote_encadre_sans_second_defilement(nav):
    """L'hôte /waf/ donne au cadre toute la hauteur annoncée : au téléphone, aucune barre interne."""
    index = (W / "index.html").read_text(encoding="utf-8")
    m = re.search(r"const HAUTEUR_MAX = \{ campagnes: (\d+) \}", index)
    assert m and int(m.group(1)) >= 12000 and "Object.prototype.hasOwnProperty.call(HAUTEUR_MAX, onglet)" in index
    p = _ouvre(nav, {}, "?demo=1&embed=1", 360)
    h = p.evaluate("Math.ceil(document.getElementById('cadre').getBoundingClientRect().height)")
    assert h < int(m.group(1))
    p.set_viewport_size({"width": 360, "height": h + 4})      # ce que fait l'hôte : la hauteur annoncée ne doit plus bouger
    p.wait_for_timeout(200)
    assert p.evaluate("Math.ceil(document.getElementById('cadre').getBoundingClientRect().height)") == h
    p.context.close()


def test_lien_du_soc_ouvre_l_onglet_campagnes_avec_les_cartes(nav):
    """/waf/#campaigns (lien de Guardian) : l'hôte ouvre l'onglet Campagnes et encadre la page, sans défilement interne à 400 px."""
    p = nav.new_context(viewport={"width": 400, "height": 800}).new_page()

    def servir(r):
        u = r.request.url.split("?")[0].split("g.test")[1]
        f = W / (u[len("/waf/"):] or "index.html")
        if u.startswith("/waf/") and f.is_file():
            return r.fulfill(status=200, content_type="text/javascript" if u.endswith(".js") else "text/html", body=f.read_text(encoding="utf-8"))
        return r.fulfill(status=404, body="")
    p.route("http://g.test/**", servir)
    p.goto("http://g.test/waf/?demo=1#campaigns")
    p.frame_locator("#pageFrame").locator("#populations article").first.wait_for(timeout=5000)
    p.wait_for_timeout(500)
    assert p.locator('#wafTabs [data-tab="campaigns"]').get_attribute("aria-selected") == "true" and p.locator("#pageCard").is_visible()
    cadre, doc = p.evaluate("(function(){var f=document.getElementById('pageFrame');return [f.clientHeight,f.contentDocument.documentElement.scrollHeight];})()")
    assert cadre > 4000 and doc <= cadre
    p.context.close()
