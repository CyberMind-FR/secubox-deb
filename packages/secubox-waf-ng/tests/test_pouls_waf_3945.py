# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Pages vivantes d'Actor et du WAF (#3945) : composant partagé chargé par la page, données réelles seulement, page fixe sans lui ;
au navigateur (sauté sans Playwright) : recul daté, mise à jour sans relance, démonstration, hostile, mouvement réduit."""
import http.server
import json
import re
import threading
import time
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
WAF, HUB = ICI / "composants/waf/www/waf", ICI.parent / "secubox-hub/www/shared"
PAGES = [WAF / f"{n}.html" for n in ("vue", "menaces", "visites", "surfaces", "tableau")] + [ICI / "www/actor/index.html"]


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_composant_charge_par_la_page_et_facultatif(page):
    src = page.read_text(encoding="utf-8")
    assert src.count("j.src='/shared/pouls.js?v=1.13.0';j.onload=vivre") == 1
    assert "if(!P||!VIE)return;" in src                                          # absent : la page reste fixe
    assert len(re.findall(r"<script(?![^>]+src=)[^>]*>", src)) == 1              # un seul script dans la page
    # Démonstration : jamais gardée ; sans donnée : aucun relevé, donc rien ne bouge.
    assert re.search(r"instantanes:!p+(?:ays)?\.length\?\[\]:", src)
    assert re.search(r"(?:d\.demo\?\[r\]|DEMO\?\[r\]|DEMO\?serveur\.concat\(\[r\]\)):P\.memoire\(", src)


def test_les_memoires_ne_melangent_pas_deux_mesures():
    cles = {p.stem: re.findall(r"P\.memoire\('([^']+)'", p.read_text(encoding="utf-8")) for p in PAGES}
    assert cles == {"vue": [], "menaces": ["waf-pays"], "visites": ["waf-visites"], "surfaces": ["waf-pays"], "tableau": ["waf-tableau"], "index": ["actor-pays"]}


# ------------------------------------------------------------------------------------------------ navigateur

PAYS = {"US": 2224, "DE": 532, "CN": 398, "<b>": 5}
REPONSES = {"/api/v1/waf/stats": {"par_origine": {"waf": 9}, "blocked_24h": 900, "by_severity": {"high": 3}, "by_category": {"sqli": 4}, "par_type": {"http": 5},
                                  "pays": PAYS, "top_countries": [{"country": k, "count": v} for k, v in PAYS.items()], "top_vhosts": [],
                                  "top_ips": {"203.0.113.7": 9}, "top_ips_countries": {"203.0.113.7": "DE"}},
            "/api/v1/waf/status": {"enabled": True, "total_rules": 3, "autoban_enabled": True},
            "/api/v1/waf/visits": {"available": True, "total": 9, "top_countries": PAYS},
            "/api/v1/waf/history": {"jours": {f"2026-11-{j:02d}": {"total": 10 * j, "severites": {"high": j}} for j in range(10, 26)}, "top_ips": {}}}


@pytest.fixture(scope="module")
def serveur():
    racines = {"/waf/": WAF, "/actor/": ICI / "www/actor", "/shared/": HUB}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            ch = self.path.split("?")[0]
            corps, ct = (json.dumps(REPONSES[ch]).encode(), "application/json") if ch in REPONSES else (None, "")
            for pre, rep in racines.items():
                f = rep / ch[len(pre):] if ch.startswith(pre) else None
                if f and f.is_file() and f.parent == rep:
                    corps, ct = f.read_bytes(), {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}.get(f.suffix, "application/octet-stream")
            self.send_response(200 if corps is not None else 404)
            self.send_header("Content-Type", ct + "; charset=utf-8")
            self.end_headers()
            if corps is not None:
                self.wfile.write(corps)

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_address[1]}"
    s.shutdown()


@pytest.fixture(scope="module")
def navigateur():
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001 — navigateur absent de la machine
            pytest.skip(f"chromium absent : {e}")
        yield b
        b.close()


@pytest.fixture
def ouvrir(navigateur, serveur):
    ouverts = []

    def _o(chemin, passe=None, sans=False, **ctx):
        c = navigateur.new_context(viewport={"width": 1280, "height": 900}, locale="fr-FR", **ctx)
        pg = c.new_page()
        pg.err = []
        pg.on("pageerror", lambda e: pg.err.append(str(e)))
        pg.on("console", lambda m: pg.err.append(m.text) if m.text.startswith("pouls") else None)
        pg.add_init_script("sessionStorage.setItem('sbx-pouls-auto','non')")
        if passe is not None:
            pg.add_init_script("for(const k of ['waf-pays','waf-top','waf-visites','waf-tableau'])if(!sessionStorage.getItem('sbx-pouls:'+k))sessionStorage.setItem('sbx-pouls:'+k,%s)" % json.dumps(json.dumps(passe)))
        if sans:
            pg.route("**/shared/pouls.js*", lambda r: r.fulfill(status=404))
        pg.goto(serveur + chemin)
        pg.wait_for_timeout(500)
        ouverts.append((c, pg))
        return pg
    yield _o
    for c, pg in ouverts:
        assert pg.err == []
        c.close()


def passe(n=6):
    t = int(time.time())
    return [{"t": t - 60 * (n - i) - 5, "pays": [{"code": "US", "n": 2000 + 10 * i}, {"code": "DE", "n": 500}]} for i in range(n)]


def date(pg):
    return pg.evaluate("(()=>{const s=document.querySelector('svg.monde');s.scrollIntoView({block:'center'});const q=s.closest('.pan').querySelector('[data-sbxp=quand]');return q?q.textContent:''})()")


def attendre(pg, motif, s=25):
    fin = time.monotonic() + s
    while not re.search(motif, date(pg)):
        assert time.monotonic() < fin, date(pg)
        pg.wait_for_timeout(30)


@pytest.mark.parametrize("nom", ["vue", "menaces", "visites", "surfaces", "tableau"])
def test_nav_waf_recul_puis_present(ouvrir, nom):
    pg = ouvrir(f"/waf/{nom}.html?embed=1", passe())
    attendre(pg, "^◀ il y a [3-6] min$")
    pg.evaluate("document.getElementById('rafraichir').click()")                 # un relevé arrive pendant le recul
    pg.wait_for_timeout(250)
    assert date(pg).startswith("◀") and pg.evaluate("document.querySelectorAll('svg[data-sbxp=carte]').length") == 1
    attendre(pg, "^● maintenant$")
    assert pg.evaluate("document.querySelectorAll('[data-sbxp=vie]').length") == 1
    assert pg.evaluate("document.querySelectorAll('.pan b img, .pan script').length") == 0


@pytest.mark.parametrize("nom", ["vue", "menaces", "tableau"])
def test_nav_waf_premier_releve_et_sans_composant(ouvrir, nom):
    assert date(ouvrir(f"/waf/{nom}.html")) == ""                                # un seul relevé : carte fixe, sans date
    pg = ouvrir(f"/waf/{nom}.html", passe(), sans=True)
    assert pg.evaluate("document.querySelectorAll('[data-sbxp]').length") == 0 and pg.evaluate("document.querySelectorAll('svg.monde *').length") > 5


def test_nav_waf_demo_jamais_gardee(ouvrir):
    pg = ouvrir("/waf/menaces.html?demo=1")
    assert date(pg) == "" and pg.evaluate("Object.keys(sessionStorage).filter(k=>k.startsWith('sbx-pouls:')).length") == 0


def test_nav_vue_points_de_la_page_gardent_survol_et_types(ouvrir):
    pg = ouvrir("/waf/vue.html", passe(), reduced_motion="reduce")
    assert date(pg) == "● maintenant"
    assert pg.evaluate("[...document.querySelectorAll('#monde .pts > g.pt')].length") == 3
    assert pg.evaluate("[...document.querySelectorAll('svg[data-sbxp=carte] circle')].filter(c=>c.getAttribute('fill-opacity')).every(c=>c.getAttribute('opacity')==='0')")
    pg.locator("#monde g.pt").first.hover(force=True)
    assert pg.evaluate("document.getElementById('tip').hidden") is False


def test_nav_actor_demo_anneau_du_moteur(ouvrir):
    pg = ouvrir("/actor/index.html?demo=1")
    attendre(pg, r"^◀ il y a 1 h \d\d$")
    attendre(pg, "^● maintenant$")
    k = pg.evaluate("[...document.querySelectorAll('#kpis .tuile')].map(t=>[t.querySelector('.v').textContent,!!t.querySelector('[data-sbxp=quand]')])")
    assert k[1] == ["136 638", True] and k[0][1] is False and k[3][1] is False and k[5][1] is True


def test_nav_actor_total_24h_jamais_change(ouvrir):
    pg = ouvrir("/actor/index.html?demo=1")
    vus, fin = set(), time.monotonic() + 14
    while time.monotonic() < fin:
        pg.evaluate("document.getElementById('kpis').scrollIntoView({block:'start'})")
        t = pg.evaluate("[...document.querySelectorAll('#kpis .tuile')].slice(1,2).map(t=>[t.querySelector('.v').textContent,t.querySelector('[data-sbxp=quand]').textContent])[0]")
        assert t[0] == "136 638"
        vus.add(t[1])
        pg.wait_for_timeout(60)
    assert any(re.match(r"^◀ \d\d:\d\d : ", x) for x in vus), vus


def test_nav_vue_repli_alertes_memoire_a_part_et_date_de_lecture(ouvrir):
    pg = ouvrir("/waf/vue.html", passe())
    pg.route("**/api/v1/waf/stats", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({**REPONSES["/api/v1/waf/stats"], "top_countries": []})))
    pg.route("**/api/v1/waf/alerts*", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps({"alerts": [{"country": "FR", "category": "sqli"}, {"country": "DE", "category": "scan"}]})))
    avant = pg.evaluate("sessionStorage.getItem('sbx-pouls:waf-top')")
    pg.evaluate("document.getElementById('rafraichir').click()")
    pg.wait_for_timeout(400)
    g = pg.evaluate("JSON.parse(sessionStorage.getItem('sbx-pouls:waf-alertes'))")
    assert avant == pg.evaluate("sessionStorage.getItem('sbx-pouls:waf-top')") and len(g) == 1
    pg.wait_for_timeout(1100)
    pg.locator("#legT button").first.click()                                     # changer de type ne relit rien : même date
    assert [x["t"] for x in pg.evaluate("JSON.parse(sessionStorage.getItem('sbx-pouls:waf-alertes'))")] == [g[0]["t"]]
