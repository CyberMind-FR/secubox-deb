# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# ruff: noqa: E702
"""#2683 — les deux entrées de configuration du WAF au profil Aurora : /waf/ (hôte des pages) et la console (www/index.html).

Tests statiques + vrai navigateur (Playwright), API simulée sur http://sbx.test, adresses de documentation uniquement.
"""
import json
import re
import time
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www"
HOTE = (WWW / "waf" / "index.html").read_text(encoding="utf-8")
CONSOLE = (WWW / "index.html").read_text(encoding="utf-8")
PAGES = {"hote": HOTE, "console": CONSOLE}


@pytest.mark.parametrize("nom", PAGES)
def test_page_autonome_sans_dialogue_natif(nom):
    s = PAGES[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    assert re.findall(r'<script src="([^"]+)"', s) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in s and "hybrid-skin" not in s and "crt-" not in s
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "Math.random", "fonts.googleapis"):
        assert interdit not in s, interdit
    assert "lorem" not in s.lower()
    assert "sbxVue" in s and "demo" in s.lower() and "embed" in s
    assert "--fond:#060d1b" in s and "--cyan:#29b6f6" in s and "--rouge:#ff4d5e" in s
    assert "localStorage.getItem('sbx_token')" in s and "h.Authorization = 'Bearer ' + t" in s
    assert 'title="' in s and "—" in s


def test_les_deux_fichiers_ne_sont_pas_des_doublons():
    assert HOTE != CONSOLE
    assert "Console WAF" in CONSOLE and "Pare-feu applicatif" in HOTE


def test_hote_routes_et_corps_a_l_identique():
    for r in ("'POST', '/ban'", "'POST', '/unban'", "'POST', '/bans/clear'", "'POST', '/mode'", "'/export'", "'POST', '/category/'",
              "'/status'", "'/stats'", "'/bans'", "'/categories'", "'/detections'", "/alerts?limit=20&aggregate=true"):
        assert r in HOTE, r
    assert "{ ip, duration: '4h', reason: 'Manual ban from WAF dashboard' }" in HOTE
    assert "{ ip }" in HOTE and "{ enabled: actif }" in HOTE and "{ enabled: actif }" in HOTE
    assert "/waf/settings.html" in HOTE


def test_hote_onglets_et_cadres_inchanges():
    pages = {"overview": "menaces", "attackers": "attaquants", "visits": "visites", "recon": "surfaces", "history": "historique", "campaigns": "campagnes"}
    for onglet, page in pages.items():
        assert f"{onglet}: '{page}'" in HOTE and f'data-tab="{onglet}"' in HOTE
        assert (WWW / "waf" / f"{page}.html").is_file()
    assert 'data-tab="vue"' in HOTE and 'src="vue.html"' in HOTE and 'switchTab("vue")' in HOTE and 'data-tab="config"' in HOTE
    assert "e.data.sbxwafVue" in HOTE and "e.data.sbxWafVue && e.data.onglet" in HOTE and "e.data.origin" not in HOTE and "e.origin !== location.origin" in HOTE
    assert 'role="tab"' in HOTE and "aria-selected" in HOTE


def test_console_routes_et_corps_a_l_identique():
    for r in ("'POST', '/ban'", "'POST', '/unban/' + ip", "'POST', '/reload'", "'POST', '/category/' + id + '/toggle'", "'/status'", "'/stats'",
              "'/categories'", "'/bans'", "/alerts?limit=15&aggregate=true", "/geoip/"):
        assert r in CONSOLE, r
    assert "{ ip, duration, reason }" in CONSOLE and "{ enabled }" in CONSOLE
    assert "Manual ban" in CONSOLE and "Manual ban from dashboard" in CONSOLE
    for lien in ("/waf/#vue", "/waf/#overview", "/waf/#campaigns", "/waf/#config"):
        assert lien in CONSOLE


def test_aucune_ecriture_hors_fonction_ecrire():
    """Toute écriture passe par ecrire(), inerte en démonstration."""
    for s in PAGES.values():
        assert "if (DEMO) return { ok: false, demo: true };" in s
        assert s.count("method: methode") == 1   # un seul point d'émission


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
STATUS = {"module": "waf", "enabled": True, "total_rules": 382, "active_categories": 3}
STATS = {"blocked_24h": 1284, "threats_today": 311, "vhosts_count": 9,
         "by_severity": {"critical": 24, "high": 80}, "by_category": {"sqli": 90, "xss": 70},
         "top_countries": [{"country": "DE", "count": 120}, {"country": "US", "count": 90}],
         "top_vhosts": [{"vhost": "app.example.test", "count": 150}],
         "top_ips": {"203.0.113.7": 61}, "top_ips_countries": {"203.0.113.7": "DE"}}
ALERTS = {"alerts": [{"client_ip": "203.0.113.41", "count": 12, "categories": ["xss", "recon"], "max_severity": "high", "last_seen": NOW,
                      "timestamp": NOW, "latest_alert": {"rule_id": "XSS-014", "description": "Balise script"}},
                     {"client_ip": "203.0.113.7", "count": 3, "categories": ["sqli"], "max_severity": "critical", "currently_banned": True, "timestamp": NOW}]}
BANS = {"total": 1, "bans": [{"value": "198.51.100.23", "scenario": "leurre", "country": "US", "duration": "24h", "created_at": NOW}]}
CATS = {"categories": {"sqli": {"name": "Injection SQL", "enabled": True, "rules_count": 64}, "xss": {"name": "Scripts intersites", "enabled": True, "rules_count": 58},
                       "robots": {"name": "Robots", "enabled": False, "rules_count": 120}}}
DETS = {"detections": [{"nom": "Hôtes non routés", "actif": True, "resume": "Un hôte non publié", "classes": ["hôte vide"], "detail": "3 vhosts"}]}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/alerts": (200, ALERTS), "/bans": (200, BANS), "/categories": (200, CATS), "/detections": (200, DETS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    p.set_default_timeout(6000)
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    cadres = []
    p.on("framenavigated", lambda f: cadres.append(f.url))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "waf":
            r.fulfill(status=200, content_type="text/html", body=HOTE)
        elif chemin.rstrip("/") == "console":
            r.fulfill(status=200, content_type="text/html", body=CONSOLE)
        elif chemin.startswith("waf/") and chemin.endswith(".html"):
            r.fulfill(status=200, content_type="text/html", body="<!doctype html><html><body>page</body></html>")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/waf", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        if chemin == "/export" and r.request.method == "GET" and statut == 200:
            r.fulfill(status=200, content_type="application/json", body=json.dumps({"logs": []}))
            return
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/waf/**", api)
    p.add_init_script("try{localStorage.setItem('sbx_token','jeton-test')}catch(e){}")
    p.goto(url)
    return ctx, p, erreurs, appels, cadres


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


# ───────────────────────── hôte /waf/ ─────────────────────────

def test_hote_tuiles_et_etat_viennent_de_l_api(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/waf/", API)
    p.wait_for_function("document.getElementById('tBans').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tMenaces", "#tJour", "#tBans", "#tRegles", "#tCats", "#tSites")] == ["1 284", "311", "1", "382", "2", "9"] or \
        [re.sub(r"\s", " ", p.inner_text(i)) for i in ("#tMenaces", "#tJour", "#tBans", "#tRegles", "#tCats", "#tSites")] == ["1 284", "311", "1", "382", "2", "9"]
    assert "ACTIF" in p.inner_text("#etat") and "382" in p.inner_text("#etat")
    assert p.get_attribute("#tMenaces >> xpath=..", "title")
    assert all(a[3] == "Bearer jeton-test" for a in appels if a[0] == "GET")
    assert err == []
    ctx.close()


def test_hote_onglet_par_defaut_et_navigation_entre_pages(navigateur):
    ctx, p, err, _, cadres = ouvre(navigateur, "http://sbx.test/waf/", API)
    assert p.is_visible("#vueCard") and not p.is_visible("#pageCard") and p.get_attribute('[data-tab="vue"]', "aria-selected") == "true"
    for onglet, page in (("overview", "menaces"), ("attackers", "attaquants"), ("visits", "visites"), ("recon", "surfaces"), ("history", "historique"), ("campaigns", "campagnes")):
        p.click(f'[data-tab="{onglet}"]')
        assert p.get_attribute("#pageFrame", "src") == page + ".html?embed=1"
        assert p.is_visible("#pageCard") and not p.is_visible("#vueCard") and p.get_attribute(f'[data-tab="{onglet}"]', "aria-selected") == "true"
    p.click('[data-tab="config"]')
    assert p.is_visible("#configCard") and not p.is_visible("#pageCard")
    assert err == []
    ctx.close()


def test_hote_hauteur_des_cadres_suit_les_messages(navigateur):
    ctx, p, _, _, _ = ouvre(navigateur, "http://sbx.test/waf/", API)
    p.evaluate("window.postMessage({sbxwafVue: 900}, location.origin)")
    p.wait_for_function("document.getElementById('vueFrame').style.height === '904px'")
    p.click('[data-tab="visits"]')
    p.evaluate("window.postMessage({sbxWafVue: 700, onglet: 'visites'}, location.origin)")
    p.wait_for_function("document.getElementById('pageFrame').style.height === '704px'")
    ctx.close()


def test_hote_ban_demande_une_confirmation_puis_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/waf/#config", API)
    p.wait_for_selector("#eventsTable tr td.mono", state="attached")
    p.locator("#eventsTable tr", has_text="203.0.113.41").get_by_text("Bannir").click()
    assert p.is_visible("#conf") and "203.0.113.41" in p.inner_text("#confTexte") and not ecritures(appels)
    p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('banni')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/ban"][0]
    assert json.loads(post[2]) == {"ip": "203.0.113.41", "duration": "4h", "reason": "Manual ban from WAF dashboard"} and post[3] == "Bearer jeton-test"
    ctx.close()


def test_hote_annuler_ne_bannit_rien_et_une_adresse_bannie_se_leve(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/waf/#config", API)
    p.wait_for_selector("#eventsTable tr td.mono", state="attached")
    p.locator("#eventsTable tr", has_text="203.0.113.41").get_by_text("Bannir").click()
    p.click("#confNon")
    assert not p.is_visible("#conf") and not ecritures(appels)
    ligne = p.locator("#eventsTable tr", has_text="198.51.100.23")
    assert ligne.get_by_text("Lever le ban").count() == 1 and ligne.get_by_text("Bannir").count() == 0
    ligne.get_by_text("Lever le ban").click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('levé')")
    assert ("POST", "/unban", '{"ip":"198.51.100.23"}') == ecritures(appels)[0][:3]
    ctx.close()


def test_hote_vider_les_bans_exporter_et_pause(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/waf/", {**API, "/export": (200, {})})
    p.wait_for_function("document.getElementById('tBans').textContent !== '—'")
    p.click("#btnClearBans")
    assert p.is_visible("#conf") and not ecritures(appels)
    p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('levés')")
    assert ("POST", "/bans/clear", None) == ecritures(appels)[0][:3]
    p.click("#btnWafToggle")
    assert p.is_visible("#conf") and "pause" in p.inner_text("#confTexte")
    p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('pause')")
    assert ("POST", "/mode", '{"enabled":false}') == ecritures(appels)[1][:3]
    with p.expect_download() as dl:
        p.click("#btnExport")
    assert dl.value.suggested_filename.startswith("waf-logs-") and ("GET", "/export") in [a[:2] for a in appels]
    assert err == []
    ctx.close()


def test_hote_categorie_desactiver_demande_confirmation_activer_non(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/waf/#config", API)
    p.wait_for_selector("#categoryPills .cat")
    p.locator("#categoryPills .cat", has_text="Injection SQL").click()
    assert p.is_visible("#conf") and not ecritures(appels)
    p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('désactivée')")
    assert ("POST", "/category/sqli/toggle", '{"enabled":false}') == ecritures(appels)[0][:3]
    p.locator("#categoryPills .cat", has_text="Robots").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('activée.')")
    assert ecritures(appels)[1][:3] == ("POST", "/category/robots/toggle", '{"enabled":true}')
    ctx.close()


def test_hote_echec_d_api_affiche_l_erreur_dans_la_page(navigateur):
    ctx, p, _, _, _ = ouvre(navigateur, "http://sbx.test/waf/#config", {**API, "/unban": (404, {"detail": "Not Found"})})
    p.wait_for_selector("#eventsTable tr td.mono", state="attached")
    p.locator("#eventsTable tr", has_text="198.51.100.23").get_by_text("Lever le ban").click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('impossible')")
    assert "Not Found" in p.inner_text("#retour") and p.get_attribute("#retour", "class").endswith("ko")
    ctx.close()


def test_hote_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/waf/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tMenaces", "#tJour", "#tBans", "#tRegles", "#tCats", "#tSites")] == ["—"] * 6 and err == []
    ctx.close()


def test_hote_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/waf/?demo=1#config", {})
    p.wait_for_selector("#eventsTable tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and not p.is_visible("#sidebar")
    assert p.get_attribute("#vueFrame", "src") == "vue.html?demo=1"
    p.locator("#eventsTable tr").first.get_by_role("button").click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    for b in ("#btnClearBans", "#btnWafToggle", "#btnExport"):
        p.click(b)
    assert [a for a in appels if "/api/v1/waf" and a[0] != "GET"] == [] and err == []
    ctx.close()


def test_hote_telephone_sans_debordement(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/waf/?embed=1#config", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#eventsTable tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


# ───────────────────────── console (www/index.html) ─────────────────────────

C_API = {"/status": (200, STATUS), "/stats": (200, STATS), "/alerts": (200, ALERTS), "/bans": (200, BANS), "/categories": (200, CATS),
         "/geoip/203.0.113.41": (200, {"country": "NL"})}
C_URL = "http://sbx.test/console/"


def test_console_tuiles_alertes_et_onglets(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, C_URL, C_API)
    p.wait_for_function("document.getElementById('activeBans').textContent !== '—'")
    assert [re.sub(r"\s", " ", p.inner_text(i)) for i in ("#threatsToday", "#totalRules", "#activeCategories", "#activeBans")] == ["311", "382", "3", "1"]
    p.wait_for_selector("#alertsList .alerte")
    assert "203.0.113.41" in p.inner_text("#alertsList") and "XSS-014" in p.inner_text("#alertsList")
    assert ("GET", "/geoip/203.0.113.41") in [a[:2] for a in appels]
    p.click('[data-tab="bans"]')
    assert p.is_visible("#bans") and not p.is_visible("#alerts") and "198.51.100.23" in p.inner_text("#bansTable") and "Prochains à expirer" in p.inner_text("#bansTable")
    p.click('[data-tab="stats"]')
    assert "203.0.113.7" in p.inner_text("#topIpsTable") and "app.example.test" in p.inner_text("#topVhosts") and p.locator("#severityStats svg circle").count() == 2
    assert err == []
    ctx.close()


def test_console_ban_manuel_formulaire_puis_confirmation(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, C_URL, C_API)
    p.wait_for_function("document.getElementById('activeBans').textContent !== '—'")
    p.click("#btnBannir")
    p.fill("#banIp", "192.0.2.55"); p.select_option("#banDuration", "24h"); p.fill("#banReason", "essai")
    p.click("#fBan button[type=submit]")
    assert p.is_visible("#conf") and not ecritures(appels)
    p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('banni')")
    post = ecritures(appels)[0]
    assert post[:2] == ("POST", "/ban") and json.loads(post[2]) == {"ip": "192.0.2.55", "duration": "24h", "reason": "essai"}
    ctx.close()


def test_console_bannir_depuis_alerte_lever_et_categorie(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, C_URL, C_API)
    p.wait_for_selector("#alertsList .alerte")
    p.locator("#alertsList .alerte", has_text="203.0.113.41").get_by_text("Bannir").click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('banni')")
    assert json.loads(ecritures(appels)[0][2]) == {"ip": "203.0.113.41", "duration": "4h", "reason": "Manual ban from dashboard"}
    p.click('[data-tab="bans"]')
    p.get_by_text("Lever le ban").first.click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('levé')")
    assert ecritures(appels)[1][:3] == ("POST", "/unban/198.51.100.23", None)
    p.click('[data-tab="categories"]')
    p.locator("#categoriesList .cat", has_text="Injection SQL").click(); p.click("#confOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('désactivée')")
    assert ecritures(appels)[2][:3] == ("POST", "/category/sqli/toggle", '{"enabled":false}')
    ctx.close()


def test_console_recharger_les_regles(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, C_URL, {**C_API, "/reload": (200, {"success": True, "rules": 382, "categories": 18})})
    p.click("#btnReload")
    p.wait_for_function("document.getElementById('retour').textContent.includes('rechargées')")
    assert "382 règles rechargées dans 18 catégories" in p.inner_text("#retour") and ecritures(appels)[0][:3] == ("POST", "/reload", None)
    ctx.close()


def test_console_sans_session_et_demonstration(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in C_API}
    ctx, p, err, _, _ = ouvre(navigateur, C_URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and [p.inner_text(i) for i in ("#threatsToday", "#totalRules", "#activeCategories", "#activeBans")] == ["—"] * 4 and err == []
    ctx.close()
    ctx, p, err, appels, _ = ouvre(navigateur, C_URL + "?demo=1", {})
    p.wait_for_selector("#alertsList .alerte")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnReload")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.locator("#alertsList .alerte").first.get_by_text("Bannir").click(); p.click("#confOk")
    assert [a for a in appels] == [] and err == []
    ctx.close()


def test_console_telephone_sans_debordement(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, C_URL + "?embed=1", C_API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#alertsList .alerte")
    for t in ("bans", "stats", "categories"):
        p.click(f'[data-tab="{t}"]')
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
