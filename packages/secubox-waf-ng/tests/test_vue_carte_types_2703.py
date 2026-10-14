# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2703 : la carte des attaques de /waf/ colorise les types de menace (couleur + forme), légende filtrante, infobulle, API simulée."""
import json
import re
from pathlib import Path

import pytest

VUE = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf" / "vue.html"
SRC = VUE.read_text(encoding="utf-8")


def test_source_sans_balisage_injecte_pour_les_nouvelles_donnees():
    bloc = SRC[SRC.index("function famille("):SRC.index("function courbe(")]
    assert "innerHTML" not in bloc and "createElementNS" in bloc and "textContent" in bloc
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "limit=500" in SRC            # même route /alerts, aucune route nouvelle
    assert not re.search(r"(src|href)=[\"']https?://|@import", SRC)


def test_au_moins_six_types_aux_couleurs_et_formes_distinctes():
    t = re.findall(r"\{id:'(\w+)',nom:'([^']+)',coul:'(#[0-9a-f]{6})',forme:'(\w+)'", SRC)
    assert len(t) >= 7
    assert len({x[2] for x in t}) == len(t)
    assert len({x[3] for x in t}) == len(t)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def al(pays, cat, n):
    return [{"timestamp": "2026-10-10T14:00:00", "client_ip": "203.0.113.%d" % (i + 1), "country": pays, "category": cat,
             "host": "h", "path": "/", "severity": "high", "action": "banned"} for i in range(n)]


STATS = {"par_origine": {"waf": 100}, "blocked_24h": 5, "by_severity": {"high": 3}, "by_category": {"sqli": 3, "xss": 1, "scan-ports": 4, "robots": 9}, "par_type": {"http": 50, "leurre": 7, "ssh": 3},
         "top_countries": [{"country": "US", "count": 40}, {"country": "DE", "count": 20}, {"country": "FR", "count": 10}, {"country": "CN", "count": 5}]}
ALERTES = {"alerts": al("US", "sql.injection", 6) + al("US", "xss", 2) + al("DE", "scan-ports", 4) + al("FR", "honeypot leurre", 3) + al("DE", "robots", 1)
           + al("US", "path traversal", 1) + al("US", "brute-force ssh", 1)}


def ouvre(nav, reponses, url="http://sbx.test/waf/vue.html", taille=None):
    ctx = nav.new_context(viewport=taille or {"width": 1400, "height": 1000})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(r):
        corps = reponses.get(r.request.url.split("?")[0].split("sbx.test")[1])
        r.fulfill(status=200 if corps is not None else 401, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://sbx.test/api/**", api)
    p.route("http://sbx.test/waf/vue.html*", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.goto(url)
    p.wait_for_selector("#monde g.pt, #pays .vide", state="attached")
    return ctx, p, erreurs


REP = {"/api/v1/waf/stats": STATS, "/api/v1/waf/status": {"enabled": True, "total_rules": 1, "autoban_enabled": True}, "/api/v1/waf/alerts": ALERTES}


def test_couleur_du_type_dominant_par_pays(nav):
    ctx, p, err = ouvre(nav, REP)
    dom = {a: p.get_attribute('#monde g.pt[data-pays="%s"]' % a, "data-dom") for a in ("US", "DE", "FR", "CN")}
    assert dom == {"US": "inj", "DE": "scan", "FR": "leurre", "CN": ""}
    # le cercle des États-Unis porte un secteur rouge (injection) et un secteur orange (script)
    cs = p.eval_on_selector_all('#monde g.pt[data-pays="US"] path[data-type]', "e=>e.map(x=>x.getAttribute('fill'))")
    assert "#ff4d5e" in cs and "#ff9f1c" in cs and len(set(cs)) == 4
    # liste : pastille du type dominant, pays sans type = gris sans type
    assert p.get_attribute('#pays [data-pays="DE"]', "data-dom") == "scan" and p.get_attribute('#pays [data-pays="CN"]', "data-dom") == ""
    assert p.locator("#pays svg").count() == 4
    assert err == []
    ctx.close()


def test_legende_comptes_et_filtre_accessible(nav):
    ctx, p, _ = ouvre(nav, REP)
    b = p.locator("#legT button")
    assert b.count() == 7 and p.get_attribute("#legT", "role") == "group"
    assert all(b.nth(i).get_attribute("aria-pressed") == "false" for i in range(b.count()))
    inj = p.locator('#legT button[data-type="inj"]')
    assert "Injection" in inj.inner_text() and inj.inner_text().split()[-1] == "6"
    inj.click()
    assert p.get_attribute('#legT button[data-type="inj"]', "aria-pressed") == "true"
    assert "att" in p.get_attribute('#monde g.pt[data-pays="DE"]', "class") and "att" not in p.get_attribute('#monde g.pt[data-pays="US"]', "class")
    p.locator('#legT button[data-type="inj"]').click()
    assert p.get_attribute('#legT button[data-type="inj"]', "aria-pressed") == "false"
    assert "att" not in p.get_attribute('#monde g.pt[data-pays="DE"]', "class")
    ctx.close()


def test_infobulle_repartition_et_pays_sans_type(nav):
    ctx, p, _ = ouvre(nav, REP)
    p.hover('#monde g.pt[data-pays="US"] circle.hal', force=True)
    assert p.is_visible("#tip")
    t = p.inner_text("#tip")
    assert "US" in t and "40 événements" in t and "Injection" in t and "6 (60 %)" in t and "sur 10 alertes récentes" in t
    p.mouse.move(2, 2)
    assert not p.is_visible("#tip")
    p.focus('#monde g.pt[data-pays="CN"]')
    assert "Type inconnu" in p.inner_text("#tip") and "5 événements" in p.inner_text("#tip")
    assert "type inconnu" in p.get_attribute('#monde g.pt[data-pays="CN"]', "aria-label")
    ctx.close()


def test_sans_alerte_aucun_type_invente(nav):
    ctx, p, err = ouvre(nav, {**REP, "/api/v1/waf/alerts": {"alerts": []}})
    assert "—" in p.inner_text("#legT") and p.locator("#legT button").count() == 0
    assert p.locator("#monde g.pt").count() == 4 and all(d == "" for d in p.eval_on_selector_all("#monde g.pt", "e=>e.map(x=>x.dataset.dom)"))
    ctx.close()


def test_categorie_hostile_en_texte(nav):
    mal = {"alerts": al("US", "<img src=x onerror=window.pwn=1>", 2)}
    ctx, p, err = ouvre(nav, {**REP, "/api/v1/waf/alerts": mal})
    assert p.evaluate("window.pwn") is None and p.get_attribute('#monde g.pt[data-pays="US"]', "data-dom") == "autre"
    ctx.close()


def test_demo_types_varies_et_annonce(nav):
    ctx, p, err = ouvre(nav, {}, "http://sbx.test/waf/vue.html?demo=1")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.locator("#legT button").count() >= 6
    assert len(set(p.eval_on_selector_all("#monde g.pt", "e=>e.map(x=>x.dataset.dom)"))) >= 5
    assert "fictive" in p.inner_text("#geoNote")
    assert err == []
    ctx.close()


def test_embed_et_420_px_sans_debordement(nav):
    for url in ("http://sbx.test/waf/vue.html?demo=1&embed=1", "http://sbx.test/waf/vue.html?demo=1"):
        for larg in (420, 700, 1400):
            ctx, p, err = ouvre(nav, {}, url, {"width": larg, "height": 900})
            assert p.evaluate("document.documentElement.scrollWidth <= innerWidth"), (url, larg)
            assert err == []
            ctx.close()
    ctx, p, _ = ouvre(nav, {}, "http://sbx.test/waf/vue.html?demo=1", {"width": 800, "height": 900})
    assert p.evaluate("document.querySelector('.legT').scrollWidth <= document.querySelector('.legT').clientWidth + 1")
    ctx.close()


def test_types_de_trafic_memes_couleurs_et_filtre_commun(nav):
    ctx, p, _ = ouvre(nav, REP)
    # donut : une ligne par famille, couleur = celle de la carte
    assert p.locator("#cats div").count() == 3
    assert p.get_attribute('#cats [data-type="inj"]', "data-type") == "inj"
    assert "#ff4d5e" in p.get_attribute("#cats [data-type=inj] svg circle", "fill")
    assert "255, 77, 94" in p.evaluate("document.getElementById('donut').style.background")
    # trafic par type : les leurres reprennent le vert et la forme des leurres, HTTP/SSH restent neutres
    assert p.get_attribute('#types .ligne[data-type="leurre"] i', "style").replace(" ", "").find("rgb(46,204,113)") >= 0
    assert p.locator("#types .ligne").count() == 3 and p.locator("#types .ligne[data-type]").count() == 1
    # tableau des événements : pastille du type
    assert p.locator("#events tr:first-child td:nth-child(4) svg").count() == 1
    # un clic sur la légende met le type en avant partout
    p.locator('#legT button[data-type="inj"]').click()
    assert "att" in p.get_attribute('#cats [data-type="scan"]', "class") and "att" not in (p.get_attribute('#cats [data-type="inj"]', "class") or "")
    assert "att" in p.get_attribute('#types .ligne[data-type="leurre"]', "class")
    assert p.locator("#events tr.att").count() > 0
    assert p.get_attribute('#legT button[data-type="inj"]', "aria-pressed") == "true"
    ctx.close()


def test_captures(nav):
    import os
    d = os.environ.get("CAPTURE_2703")
    if not d:
        pytest.skip("captures a la demande")
    for larg in (1400, 420, 800):
        ctx, p, _ = ouvre(nav, {}, "http://sbx.test/waf/vue.html?demo=1", {"width": larg, "height": 1000})
        p.screenshot(path="%s/carte_%d.png" % (d, larg), full_page=True)
        ctx.close()
