# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2682 — Actor Intelligence et le poste de garde WAF au profil Aurora : tests statiques + vrai navigateur, API simulée (sbx.test)."""
import json
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAGES = {"actor": RACINE / "www" / "actor" / "index.html", "tableau": RACINE / "composants" / "waf" / "www" / "waf" / "tableau.html"}
SRC = {k: v.read_text(encoding="utf-8") for k, v in PAGES.items()}


@pytest.mark.parametrize("nom", list(PAGES))
def test_page_autonome_sans_dialogue_natif(nom):
    s = SRC[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    scripts = re.findall(r'<script[^>]*\bsrc=', s)
    assert scripts == [] and "hybrid" not in s and "googleapis" not in s and "<link" not in s
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "Math.random"):
        assert interdit not in s, interdit
    assert "lorem" not in s.lower() and "demo" in s.lower() and "embed" in s and "sbxVue" in s
    assert "localStorage.getItem('sbx_token')" in s and "'Bearer '" in s


def test_actor_lecture_seule_memes_routes():
    s = SRC["actor"]
    for r in ("/api/v1/actor/stats", "/api/v1/actor/actors", "/api/v1/actor/campaigns", "/api/v1/actor/overview"):
        assert r in s
    assert "POST" not in s and "method:" not in s
    assert "onglet:'actor'" in s and "/shared/sidebar.js" in s


def test_tableau_lecture_seule_memes_routes():
    s = SRC["tableau"]
    for r in ("'/stats'", "'/history'", "'/bans'", "'/detections'", "'/campaigns'", "/api/v1/waf"):
        assert r in s
    assert "POST" not in s and "method:" not in s and "onglet:'tableau'" in s
    assert "/login.html?redirect=" in s


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, nom, chemin_url, api, taille=None):
    """api : {chemin_api: (statut, corps)} ; sbx.test sert la page, /shared/ vide."""
    ctx = nav.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        c = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if c.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if c.endswith(".css") else "application/javascript", body="")
        elif c.startswith("page/"):
            r.fulfill(status=200, content_type="text/html", body=SRC[nom])
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def apif(r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1]
        appels.append((r.request.method, u, r.request.headers.get("authorization")))
        c = u.split("?")[0]
        st, corps = api.get(c, (404, {}))
        r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", apif)
    p.add_init_script("try{localStorage.setItem('sbx_token','tok123')}catch(e){}") if False else None
    p.goto("http://sbx.test/page/" + chemin_url)
    return ctx, p, erreurs, appels


ACT = {"id": "ACT-1", "priority": 62, "level": "LOW", "bans": 2, "src": {"ips": 9, "asns": 3, "countries": 3}, "first": "a", "last": "b",
       "targets": ["x.test", "y.test"], "vec": {"continuity": 88, "automation": 80, "intent": 64}, "hyp": [["campagne ciblée", .6]], "tags": []}
ACT_XSS = dict(ACT, id="<img src=x onerror=window.xss=1>", src={"ips": 1, "asns": 1, "countries": 1}, bans=0)
STATS = {"posture": "Protégée", "mode": "observe", "blocked_24h": 0, "attempts_24h": 5, "actors": 2, "campaigns": 1, "events_24h": 9}
OVER = {"top_pays": [{"code": "US", "n": 9}], "recents": [{"ts": 1760000000, "acteur": "<b>z</b>", "type": "<i>t</i>", "module": "m", "score": 80}],
        "robots": [{"famille": "Googlebot<script>", "hits": 7, "ips": 2}], "activite_acteurs": {"ACT-1": list(range(24))}, "techniques": {"ACT-1": [{"nom": "sql.injection", "n": 3}]}}
API_ACTOR = {"/api/v1/actor/stats": (200, STATS), "/api/v1/actor/actors": (200, [ACT, ACT_XSS]),
             "/api/v1/actor/campaigns": (200, [{"signature": "sig", "nb_acteurs": 2, "sources": 4, "cibles": ["x"], "cibles_inexistantes": 0, "pays": 1, "acteurs": ["ACT-1"]}]),
             "/api/v1/actor/overview": (200, OVER)}


def test_actor_valeurs_serveur_jamais_interpretees_et_zero_est_une_mesure(nav):
    ctx, p, err, appels = ouvre(nav, "actor", "actor.html", API_ACTOR)
    p.wait_for_selector("#kpis .tuile")
    t = p.inner_text("#kpis")
    assert "Bloquées\n0" in t.replace("\n\n", "\n")          # 0 est une mesure, pas « — »
    p.click("text=Tous")
    p.wait_for_selector("#list .acteur")
    assert p.evaluate("window.xss") is None and p.locator("#even img, #even b, #even i, #list img, #tuiles script").count() == 0
    assert "<b>z</b>" in p.inner_text("#even") and "Googlebot<script>" in p.inner_text("#tuiles")
    assert all(a[0] == "GET" for a in appels) and err == []
    ctx.close()


def test_actor_profil_activite_techniques(nav):
    ctx, p, err, _ = ouvre(nav, "actor", "actor.html", API_ACTOR)
    p.wait_for_selector("#profile .pid")
    assert p.inner_text("#profile .pid") == "ACT-1"
    assert "Techniques observées" in p.inner_text("#profile").replace("TECHNIQUES OBSERVÉES", "Techniques observées") and p.locator("#profile svg.actv").count() == 1
    assert "sql.injection" in p.inner_text("#profile") and err == []
    ctx.close()


def test_actor_jeton_en_bearer(nav):
    ctx, p, _, appels = ouvre(nav, "actor", "actor.html", API_ACTOR)
    p.evaluate("localStorage.setItem('sbx_token','tok123')")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert any(a[2] == "Bearer tok123" for a in appels)
    ctx.close()


def test_actor_moteur_absent_et_session_requise(nav):
    ctx, p, err, _ = ouvre(nav, "actor", "actor.html", {})
    p.wait_for_selector("#moteur:not([hidden])")
    assert "nouvel essai automatique" in p.inner_text("#list") and p.inner_text("#etat") == "MOTEUR INJOIGNABLE" and err == []
    ctx.close()
    ctx, p, err, _ = ouvre(nav, "actor", "actor.html", {k: (401, {}) for k in API_ACTOR})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE" and err == []
    assert p.inner_text("#tuiles .tuile .v").strip() == "—"
    ctx.close()


def test_actor_demo_annoncee_aucun_appel(nav):
    ctx, p, err, appels = ouvre(nav, "actor", "actor.html?demo=1", {})
    p.wait_for_selector("#profile .pid")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and appels == [] and err == []
    ctx.close()


def test_actor_embed_420_sans_debordement_ni_menu(nav):
    ctx, p, err, _ = ouvre(nav, "actor", "actor.html?embed=1", API_ACTOR, taille={"width": 420, "height": 800})
    p.wait_for_selector("#list .acteur")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_actor_maitre_detail_petit_ecran(nav):
    ctx, p, _, _ = ouvre(nav, "actor", "actor.html?embed=1", API_ACTOR, taille={"width": 420, "height": 800})
    p.wait_for_selector("#list .acteur")
    assert not p.is_visible("#colProfil")
    p.locator("#list .acteur").first.click()
    assert p.is_visible("#colProfil") and not p.is_visible("#colListe")
    p.click("#retour")
    assert p.is_visible("#colListe")
    ctx.close()


TAB = {"/api/v1/waf/stats": (200, {"total_threats": 10, "threats_today": 0, "par_type": {"http": 4, "ssh": 1}, "par_origine": {"waf": 4, "authwatch": 1},
                                   "top_ips": {"203.0.113.7": 50}, "top_ips_countries": {"203.0.113.7": "DE"}, "efficacite": {"sqli": {"banned": 3, "robot": 1, "warning": 1, "detect": 5}},
                                   "comptes_vises": {"<b>root</b>": 3}, "noms_non_routes": {"x.test": 2}}),
       "/api/v1/waf/history": (200, {"jours": {"2026-10-01": {"total": 5, "categories": {"sqli": 5}}, "2026-10-02": {"total": 8, "categories": {"sqli": 3, "xss": 5}}}}),
       "/api/v1/waf/bans": (200, {"total": 1, "bans": [{"ip": "203.0.113.7", "duration": "1 h"}]}),
       "/api/v1/waf/detections": (200, {"detections": [{"emoji": "x", "nom": "Anti-robots", "actif": True, "detail": "d"}]}),
       "/api/v1/waf/campaigns": (200, {"campagnes": [{"signature": "abcdef012345", "outil": "scanner", "nb_attaquants": 1, "sondes": 9, "haute_valeur": 0, "attaquants": ["203.0.113.7"], "exemple_sequence": ["/.env"]}]})}


def test_tableau_donnees_reelles_et_zero_est_une_mesure(nav):
    ctx, p, err, appels = ouvre(nav, "tableau", "tableau.html", TAB)
    p.wait_for_selector("#attaquants .acteur")
    t = p.inner_text("#tuiles")
    assert "10" in t and "Aujourd’hui\n0" in t.replace("\n\n", "\n")
    assert p.inner_text("#liveTxt").startswith("actif · 1 ban")
    assert "BANNI" in p.inner_text("#attaquants") and "<b>root</b>" in p.inner_text("#comptesVises")
    assert p.locator("#comptesVises b").count() == 0 and p.locator("#evolution rect").count() == 3
    assert "% écarté" in p.inner_text("#efficaciteResume") and not p.evaluate("document.getElementById('efficaciteDetails').open")
    assert all(a[0] == "GET" for a in appels) and err == []
    ctx.close()


def test_tableau_sans_session_tirets_et_bandeau(nav):
    ctx, p, err, _ = ouvre(nav, "tableau", "tableau.html", {k: (401, {}) for k in TAB})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#liveTxt") == "session requise" and p.locator("#tuiles .v").all_inner_texts() == ["—"] * 5 and err == []
    assert "/login.html?redirect=" in p.get_attribute("#lienLogin", "href")
    ctx.close()


def test_tableau_demo_et_telephone(nav):
    ctx, p, err, appels = ouvre(nav, "tableau", "tableau.html?demo=1&embed=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#attaquants .acteur")
    assert p.is_visible("#demo") and appels == [] and err == [] and not p.is_visible("#navVue")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    ctx.close()
