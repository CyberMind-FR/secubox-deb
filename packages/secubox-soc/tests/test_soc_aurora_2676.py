# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2676 — /soc/ (Vigie SOC) au profil Aurora : tests statiques + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "soc" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
ROUTES_LUES = ["/waf/stats", "/waf/alerts?aggregate=true&limit=400", "/waf/campaigns", "/waf/bans", "/metrics/overview",
               "/metrics/health/summary", "/profiles/lifecycles", "/metrics/vhost-stats", "/metrics/live-hosts",
               "/metrics/cert-status", "/sensor/gsm/status", "/sensor/gsm/components", "/sensor/gsm/alerts", "/soc/summary"]


def test_page_autonome_sans_dialogue_natif_ni_innerhtml():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "<script src=" not in SRC and not re.search(r"(src|href)=[\"']https?://|@import|fonts\.googleapis", SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "hybrid-"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower() and "sbxVue" in SRC and 'onglet: "soc"' in SRC
    assert "demo" in SRC and "embed" in SRC and "/shared/sidebar.js" in SRC
    assert "min-height:100vh" not in SRC and "documentElement.scrollHeight" not in SRC


def test_lecture_seule_memes_routes_et_jeton():
    for r in ROUTES_LUES:
        assert f'"{r}"' in SRC, r
    assert "POST" not in SRC and "method:" not in SRC
    assert 'localStorage.getItem("sbx_token")' in SRC and '"Bearer "' in SRC and "try {" in SRC


@pytest.fixture(scope="module")
def navigateur():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
REP = {
    "/waf/stats": {"counters": {"total_threats": 1000, "observed_threats": 250, "by_category": {"sqli": 400, "leurre:telnet": 90, "<b>x</b>": 5}}},
    "/waf/alerts": {"alerts": [{"ip": "192.0.2.1", "country": "FR", "count": 300}, {"ip": "192.0.2.2", "country": "CN", "count": 1500}]},
    "/waf/campaigns": {"available": True, "attaquants": 4, "campagnes": [{"signature": "scan-wp", "attaquants": 3, "sondes": 40}]},
    "/waf/bans": {"total": 2, "application": {"ok": True}, "bans": [{"ip": "192.0.2.1", "severity_max": "high", "categories": {"sqli": 1}, "last_seen": NOW}, {"ip": "198.51.100.2", "severity_max": "low", "categories": ["xss"], "last_seen": NOW - 99}]},
    "/metrics/overview": {"disk": {"percent": 90, "used": "9 Go", "total": "10 Go"}, "memory": {"percent": 30, "used": "1 Go", "total": "4 Go"}, "cpu": {"load1": 0.5}},
    "/metrics/health/summary": {"overall": "green", "services_ok": 10},
    "/profiles/lifecycles": {"lifecycles": [{"id": "m1", "lifecycle": "toujours", "sleep_state": "awake"}, {"id": "m2", "lifecycle": "a-la-demande", "sleep_state": "asleep", "portal_domain": "m2.exemple.test"}]},
    "/metrics/vhost-stats": {"total": 7}, "/metrics/live-hosts": {"total": 3},
    "/metrics/cert-status": {"certificates": [{"days_left": 10}, {"days_left": 90}]},
    "/sensor/gsm/status": {"overall": "green", "states": {"sdr": "ok"}},
    "/sensor/gsm/components": {"components": [{"name": "sdr", "state": "ok", "detail": "branché"}]},
    "/sensor/gsm/alerts": {"alerts": [{"id": 3, "score": 70, "cell_id": "208-1", "reason": "inconnue", "ts": NOW}]},
    "/soc/summary": {"alerts": {"unacknowledged": 1, "critical": 0}, "tickets": {"open": 2, "total": 4}},
}


def ouvre(navigateur, url, reponses, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "soc":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin.endswith(".html"):
            r.fulfill(status=200, content_type="text/html", body="<!doctype html><p>vue</p>")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1", 1)[1].split("?")[0]
        appels.append((r.request.method, r.request.url.split("/api/v1", 1)[1], r.request.headers.get("authorization")))
        if chemin in reponses:
            statut, corps = reponses[chemin]
        else:
            statut, corps = 404, {}
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


OK = {k: (200, v) for k, v in REP.items()}


def test_tuiles_et_listes_viennent_de_l_api_avec_le_jeton(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/soc/", OK)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_function("document.getElementById('p-total').textContent !== '—'")
    p.wait_for_function("document.querySelectorAll('#chaine .maillon').length === 4")
    assert [p.inner_text(i) for i in ("#p-obs", "#p-bans", "#s-vh", "#s-ho", "#s-ce")] == ["250", "2", "7", "3", "2"]
    assert "1" in p.inner_text("#p-total") and p.inner_text("#etat-flux") == "FLUX WAF ACTIF"
    assert p.inner_text("#m-disque") == "90 %" and "alerte" not in p.inner_text("#m-sante")
    assert p.evaluate("document.querySelector('#m-disque').className") == "v r"
    assert "<b>x</b>" in p.inner_text("#p-cats") and p.locator("#p-cats b").count() == 0   # texte, jamais du HTML
    assert p.locator("#carte-bulles circle").count() == 2 and p.locator("#carte-terre circle").count() > 500
    assert p.locator("#bans .evt").count() == 2 and p.locator("#centrale .evt").count() == 3
    assert "telnet" in p.inner_text("#leurres") and "m2" in p.inner_text("#dorment")
    assert all(m == "GET" for m, *_ in appels) and any(a[2] == "Bearer jeton-test" for a in appels)
    chemins = {a[1] for a in appels}
    assert {"/waf/alerts?aggregate=true&limit=400", "/waf/stats", "/soc/summary"} <= chemins
    assert err == []
    ctx.close()


def test_chaque_tuile_a_une_infobulle_de_definition(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/soc/", OK)
    assert p.evaluate("[...document.querySelectorAll('.tuile')].every(t => (t.title || '').length > 20)")
    assert p.locator(".tuile").count() == 11
    ctx.close()


def test_mesure_absente_est_un_tiret_pas_un_zero(navigateur):
    vide = {k: (200, {}) for k in REP}
    vide["/waf/bans"] = (500, {})
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/soc/", vide)
    p.wait_for_function("document.getElementById('p-bans-s').textContent.includes('illisible')")
    p.wait_for_function("document.querySelectorAll('#chaine .maillon').length === 4")
    assert [p.inner_text(i) for i in ("#p-bans", "#m-disque", "#m-mem", "#m-charge", "#m-sante", "#s-vh", "#s-ho")] == ["—"] * 7
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in REP}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/soc/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat-flux") == "SESSION REQUISE"
    assert p.inner_text("#p-total") == "—" and p.inner_text("#m-disque") == "—" and err == []
    ctx.close()


def test_bans_non_appliques_sont_signales(navigateur):
    rep = dict(OK)
    rep["/waf/bans"] = (200, {"total": 0, "bans": [], "application": {"ok": False, "detail": "table nft absente"}})
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/soc/", rep)
    p.click("#t1")
    p.wait_for_selector("#bans .panne")
    assert "NON appliqués" in p.inner_text("#bans-n") and "table nft absente" in p.inner_text("#bans .panne")
    assert p.inner_text("#p-bans") == "0"
    ctx.close()


def test_onglets_gardent_les_ecrans_et_encadrent_les_vues(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/soc/", OK)
    assert p.is_visible("#e0") and not p.is_visible("#e1")
    p.click("#t2")
    assert p.is_visible("#e2") and p.get_attribute("#t2", "aria-selected") == "true" and not p.is_visible("#e0")
    p.click("#tm")
    assert p.get_attribute("#vueFrame", "src") == "/waf/menaces.html?embed=1" and p.is_visible("#e4")
    p.click("#tn")
    assert p.get_attribute("#vueFrame", "src") == "reseau.html?embed=1"
    assert err == []
    ctx.close()


def test_la_hauteur_de_la_vue_encadree_suit_son_annonce(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/soc/", OK)
    p.click("#tm")
    p.wait_for_function("document.getElementById('vueFrame').contentDocument.body && document.getElementById('vueFrame').contentDocument.body.textContent.includes('vue')")
    cadre = [f for f in p.frames if f.url.endswith("/waf/menaces.html?embed=1")][0]
    cadre.evaluate("parent.postMessage({sbxWafVue: 900, onglet: 'menaces'}, location.origin)")
    p.wait_for_function("document.getElementById('vueFrame').style.height === '904px'")
    ctx.close()


def test_demonstration_annoncee_sans_appel_ni_menu(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/soc/?demo=1", {})
    p.wait_for_function("document.querySelectorAll('#chaine .maillon').length === 4")
    assert p.is_visible("#demo") and not p.is_visible("#session") and "démonstration" in p.inner_text("#demo").lower()
    assert [a for a in appels if a[1].startswith("/")] == [] and err == []
    assert p.inner_text("#p-total") .replace("\u202f", " ") == "1 284" and not p.is_visible("#sidebar")
    assert "demo=1" in p.get_attribute("#guardianFrame", "src")
    ctx.close()


def test_menu_commun_hors_embed_et_hors_demo(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/soc/", OK)
    assert p.locator("script[src='/shared/sidebar.js']").count() == 1
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/soc/?embed=1", OK)
    assert p.locator("script[src='/shared/sidebar.js']").count() == 0
    ctx.close()


@pytest.mark.parametrize("ecran", ["t1", "t2", "t3"])
def test_telephone_sans_debordement(navigateur, ecran):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/soc/?demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_function("document.querySelectorAll('#chaine .maillon').length === 4")
    p.click("#" + ecran)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()
