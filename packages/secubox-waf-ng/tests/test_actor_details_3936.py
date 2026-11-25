# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3936 — profil d'acteur complet et lisible, mini-histogrammes : vrai navigateur, API simulée (sbx.test)."""
import json
import re
import time
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
HTML = (RACINE / "www" / "actor" / "index.html").read_text(encoding="utf-8")
REPERES = (RACINE / "www" / "actor" / "reperes.js").read_text(encoding="utf-8")

playwright = pytest.importorskip("playwright.sync_api")


def test_un_seul_script_en_ligne_et_aucune_dependance():
    assert len(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", HTML)) == 1
    assert "asns" not in HTML.replace("asns:0", "")      # jamais affiché comme une mesure
    assert "setInterval" in HTML and "requestAnimationFrame" not in HTML
    assert "prefers-reduced-motion" in HTML


def test_texte_du_profil_lisible():
    css = HTML[HTML.index("/* profil (#3936)"):HTML.index("  .flow{display:grid")]
    tailles = [float(x) for x in re.findall(r"font-size:([0-9.]+)rem", css)]
    assert tailles and min(tailles) >= .85
    assert "var(--faible)" not in css


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
H0 = (NOW // 3600 - 23) * 3600


def acteur(i, **k):
    return dict({"id": f"ACT-{i:04d}", "priority": 60, "level": "MED", "bans": 4, "src": {"ips": 2454, "asns": 0, "countries": 88}, "first": "08:00", "last": "09:00",
                 "premier": NOW - 15 * 86400, "dernier": NOW - 240, "nb_cibles": 3, "tags": [], "hyp": [["campagne ciblée automatisée", 0], ["bruit non relié", 0]],
                 "vec": {"severity": 75, "continuity": 40, "automation": 5, "persistence": 0, "confidence": 66, "knowledge": 10}}, **k)


def serie(v):
    return {"debut": H0, "pas": 3600, "valeurs": v}


def detail(**k):
    nuls = [None] * 20
    return dict({"genere_le": NOW, "couverture_depuis": NOW - 4 * 3600, "premier_borne": False, "heures": serie(nuls + [0, 5, 9, 2]),
                 "semaine": {"debut": (NOW // 3600 - 167) * 3600, "pas": 3600, "valeurs": [None] * 164 + [0, 5, 9, 2]},
                 "jours": {"debut": (NOW // 86400 - 14) * 86400, "pas": 86400, "valeurs": [None] * 14 + [16], "partielles": [14]},
                 "series": {"bans": serie(nuls + [0, 1, 1, 0]), "adresses": serie([None] * 24), "pays": None, "nb_cibles": None},
                 "tendance": {"evenements": None, "bans": {"dernieres_24h": 4, "precedentes_24h": 9}, "adresses": None, "pays": None, "nb_cibles": None},
                 "modules": [{"nom": "waf", "n": 16}], "techniques": [{"nom": "sqli<b>x</b>", "n": 16}],
                 "pays": {"adresses": 40, "top": [{"code": "US", "part": 56}, {"code": "<i", "part": 4}]},
                 "reseaux": {"adresses_examinees": 2454, "classes": {"proxy_loue": 87, "hebergeur": 13}, "operateurs": [{"nom": "<img src=x onerror=window.xss=1>", "classe": "hebergeur", "part": 13}]},
                 "dernier_ban": NOW - 900, "mesure": {"niveau": "TARPIT", "reste_s": 60},
                 "campagnes": [{"signature": "s1", "famille": "collecte", "nb_acteurs": 3, "sources": 9, "rotation": True}]}, **k)


CAMP = {"signature": "s1", "nb_acteurs": 3, "sources": 9, "pays": 2, "cibles": ["forge.secubox.in"], "cibles_noms": ["forge.secubox.in"], "cibles_inexistantes": 0,
        "acteurs": ["ACT-0000"], "premier": NOW - 86400, "dernier": NOW - 60, "famille": "collecte", "classes": {"proxy_loue": 100}, "pays_top": []}


class Banc:
    def __init__(self, nav, n=3, det=None, taille=None, url="?embed=1", reduit=False):
        self.acts, self.det, self.appels, self.erreurs = [acteur(i) for i in range(n)], det if det is not None else detail(), [], []
        self.ctx = nav.new_context(viewport=taille or {"width": 1280, "height": 900}, reduced_motion="reduce" if reduit else "no-preference", timezone_id="Europe/Paris", locale="fr-FR")
        self.p = self.ctx.new_page()
        self.p.on("pageerror", lambda e: self.erreurs.append(str(e)))
        self.p.route("http://sbx.test/**", self._sert)
        self.p.goto("http://sbx.test/page/actor.html" + url)
        self.p.wait_for_selector("#profile .resume", state="attached")

    def _sert(self, r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1]
        if u.startswith("/page/reperes.js"):
            return r.fulfill(status=200, content_type="application/javascript", body=REPERES)
        if u.startswith("/page/"):
            return r.fulfill(status=200, content_type="text/html", body=HTML)
        self.appels.append(u)
        return r.fulfill(status=200, content_type="application/json", body=json.dumps(self.api(u)))

    def api(self, u):
        if u.startswith("/api/v1/actor/stats"):
            return {"posture": "Protégée", "mode": "observe", "blocked_24h": 5, "attempts_24h": 2, "actors": len(self.acts), "campaigns": 1, "events_24h": 7}
        if u.startswith("/api/v1/actor/activite"):
            ids = re.search(r"ids=([^&]*)", u)
            ids = ids.group(1).split(",") if ids else []
            vals = {i: ([0] * 24 if n == 1 else [None] * 24 if n == 2 else [None] * 22 + [3, 1]) for n, i in enumerate(ids)}
            return {"debut": H0, "pas": 3600, "evenements": [None] * 20 + [1, 2, 3, 1], "bloques": [None] * 20 + [1, 1, 1, 0], "acteurs": vals, "campagnes": {"s1": [1] * 24}}
        m = re.match(r"/api/v1/actor/actors/(ACT-\d+)", u)
        if m:
            return dict(next(a for a in self.acts if a["id"] == m.group(1)), detail=self.det)
        if u.startswith("/api/v1/actor/actors"):
            return self.acts
        if u.startswith("/api/v1/actor/campaigns"):
            return [CAMP]
        if u.startswith("/api/v1/waf/populations"):
            return {"populations": [{"campagne_actord": "s1", "famille": "collecte", "cibles": ["forge.secubox.in"]}]}
        return {}

    def fin(self):
        assert self.erreurs == []
        self.ctx.close()


def test_profil_complet_en_clair(nav):
    b = Banc(nav)
    b.p.wait_for_selector("#profile .duo svg.actv")
    t = b.p.inner_text("#profile .resume").replace(" ", " ")
    assert t == ("Aspire forge depuis 15 jours, depuis 2 454 adresses de 88 pays ; actif maintenant (il y a 4 min) ; 4 bans, "
                 "le dernier il y a 15 min ; en ce moment retenu (tarpit).")
    tout = b.p.inner_text("#profile")
    for x in ("DEFCON 3 · 4 bans", "fort · 75", "moyen · 40", "faible · 5", "aucun signe · 0", "pas encore d’hypothèse", "proxy loué 87 %", "pare-feu applicatif (WAF)",
              "même population que « Collecte : forge » dans le Radar", "Compté depuis le"):
        assert x in tout, x
    assert "ASN" not in tout and "Intention — vise quelque chose de précis\n—" in tout       # axe absent = « — »
    chiffres = b.p.locator("#profile .gr .v").all_inner_texts()
    assert chiffres == ["2 454", "88", "3", "4"]
    assert "▼ 4 en 24 h (−5)" in b.p.locator("#profile .gr").nth(3).inner_text()
    # adresses : tendance et série non mesurées, rien d'inventé
    assert b.p.locator("#profile .gr").nth(0).locator(".t").inner_text() == "" and b.p.locator("#profile .gr").nth(0).locator("rect").count() == 0
    assert b.p.locator("#profile .gr").nth(3).locator("rect").count() == 4
    # 24 h : quatre heures mesurées, dont un zéro ; aucune barre pour les autres
    assert b.p.locator("#profile .duo svg.actv rect").count() == 4 and b.p.locator("#profile .duo svg.actv rect.z").count() == 1
    assert b.p.locator("#profile .j7 svg.ch rect").count() == 4
    assert "20 h non mesurées" in b.p.get_attribute("#profile .duo svg.actv", "aria-label")
    # rien n'est interprété
    assert b.p.evaluate("window.xss") is None and b.p.locator("#profile img").count() == 0
    b.fin()


def test_les_morceaux_sans_mesure_disparaissent(nav):
    b = Banc(nav, det=detail(heures=None, semaine=None, jours=None, series=None, tendance=None, pays=None, reseaux=None, dernier_ban=None, mesure=None, campagnes=[], modules=[], techniques=[], couverture_depuis=0))
    b.p.wait_for_selector("#profile .duo")
    b.acts[0] = acteur(0, premier=0, dernier=0, bans=0, src={"ips": 1, "asns": 0, "countries": 0})
    b.p.click("#rafraichir")
    b.p.wait_for_function("document.querySelector('#profile .resume').textContent==='Vu depuis 1 adresse\\u202F; jamais banni.'")
    t = b.p.inner_text("#profile")
    assert t.count("— pas mesurée") == 2 and "undefined" not in t and "NaN" not in t and "Dans aucune campagne" in t
    assert b.p.locator("#profile .vif").count() == 0 and b.p.locator("#profile .quand").count() == 0
    b.fin()


def test_detail_occupe_ou_absent_est_dit(nav):
    b = Banc(nav, det=False)
    b.p.wait_for_function("document.querySelector('#profile').textContent.includes('détail indisponible')")
    assert "2 454" in b.p.inner_text("#profile .gros")
    b.fin()


def test_lignes_mini_barres_par_lots_de_60(nav):
    b = Banc(nav, n=150)
    b.p.click("text=Tous")
    b.p.wait_for_selector("#list .acteur svg.mini")
    assert b.p.locator("#list .acteur").count() == 60
    l = b.p.locator("#list .acteur")
    assert "total 4" in l.nth(0).locator("svg.mini").get_attribute("aria-label")
    assert l.nth(1).locator("rect.z").count() == 24 and l.nth(2).locator(".mini0").inner_text() == "—"
    b.p.click("#list .plus")
    b.p.wait_for_function("document.querySelectorAll('#list .acteur').length===120")
    b.p.wait_for_function("document.querySelectorAll('#list .acteur svg.mini').length>60")
    lots = [len(re.search(r"ids=([^&]*)", u).group(1).split(",")) for u in b.appels if "/activite?ids=" in u]
    assert lots and max(lots) <= 60
    assert b.p.locator("#kpis svg.mini").count() == 3       # seulement où une série existe
    b.fin()


def test_relecture_garde_selection_volets_defilement_et_focus(nav):
    b = Banc(nav, n=150)
    b.p.click("text=Tous")
    b.p.wait_for_selector("#list .acteur svg.mini")
    b.p.locator("#list .acteur").nth(5).click()
    b.p.wait_for_function("document.querySelector('#profile .pid').textContent==='ACT-0005'&&document.querySelector('#profile .duo')")
    b.p.locator("#profile details.pli summary").first.click()
    b.p.evaluate("document.querySelector('#list').scrollTop=800")
    b.p.locator("#list .acteur").nth(12).focus()
    b.p.evaluate("document.querySelector('#list').scrollTop=800;window.scrollTo(0,300)")
    b.acts[5]["bans"] = 5
    avant = b.p.evaluate("scrollY")
    b.p.evaluate("document.getElementById('rafraichir').click()")
    b.p.wait_for_function("document.querySelectorAll('#profile .gr .v')[3].textContent==='5'")
    assert b.p.locator("#profile .gr .v.chg").count() == 1
    assert b.p.inner_text("#profile .pid") == "ACT-0005" and b.p.evaluate("document.querySelector('#profile details.pli').open")
    assert b.p.evaluate("document.querySelector('#list').scrollTop") == 800 and b.p.evaluate("scrollY") == avant
    assert b.p.evaluate("document.activeElement.getAttribute('data-cle')") == "act:ACT-0012"
    b.fin()


def test_mouvement_reduit_rien_ne_bouge(nav):
    b = Banc(nav, reduit=True)
    b.p.wait_for_selector("#profile .duo svg.actv")
    b.acts[0]["bans"] = 9
    b.p.evaluate("document.getElementById('rafraichir').click()")
    b.p.wait_for_function("document.querySelectorAll('#profile .gr .v')[3].textContent==='9'")
    assert b.p.locator(".chg").count() == 0 and b.p.evaluate("document.getAnimations().length") == 0
    b.fin()


def test_campagne_du_profil_ouvre_l_onglet(nav):
    b = Banc(nav)
    b.p.click("text=Tous")
    b.p.wait_for_selector("#profile .campl")
    b.p.click("#profile .campl")
    b.p.wait_for_selector("#list .acteur.camp.on")
    assert b.p.locator(".fb[aria-selected=true]").inner_text().startswith("Campagnes")
    assert b.p.locator("#list .camp svg.mini").count() == 1
    b.fin()


def test_listes_lourdes_une_fois_par_minute(nav):
    b = Banc(nav)
    b.p.wait_for_selector("#profile .duo")
    b.p.evaluate("tick()")
    b.p.wait_for_timeout(300)
    lourds = [u for u in b.appels if u == "/api/v1/actor/actors"]
    assert len(lourds) == 1 and len([u for u in b.appels if u == "/api/v1/actor/stats"]) == 2
    assert all("actors/ACT-0000" in u for u in b.appels if "/actors/" in u)
    b.fin()


@pytest.mark.parametrize("largeur", [400, 1000, 1280])
def test_aucun_debordement(nav, largeur):
    b = Banc(nav, taille={"width": largeur, "height": 900})
    b.p.click("text=Tous")
    b.p.locator("#list .acteur").first.click()
    b.p.wait_for_selector("#profile .duo svg.actv")
    b.p.evaluate("document.querySelectorAll('#profile details').forEach(d=>d.open=true)")
    assert b.p.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
    assert b.p.evaluate("[...document.querySelectorAll('#profile *')].filter(e=>[...e.childNodes].some(n=>n.nodeType===3&&n.textContent.trim())&&parseFloat(getComputedStyle(e).fontSize)<13.59).length") == 0
    b.fin()


def test_demo_aucun_appel_et_donnees_fictives(nav):
    b = Banc(nav, url="?demo=1")
    assert b.appels == [] and b.p.locator("#profile .gr").count() == 4
    demo = HTML[HTML.index("function demoActs("):HTML.index("function maj(")]
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", demo) and "Math.random" not in demo
    b.fin()
