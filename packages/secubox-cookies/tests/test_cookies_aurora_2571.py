# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /cookies/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "cookies" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'cookies'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "window.location" not in SRC   # plus de redirection brutale sur 401 : bandeau


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/config'", "'/scan'", "'/tracker/add'", "'/tracker/' + encodeURIComponent", "'/policy'", "'/policy/' + encodeURIComponent", "'DELETE'", "include_third_party",
              "max_cookie_age_days", "block_third_party", "block_trackers", "require_consent", "category"):
        assert r in SRC
    assert "cookie-crosssite?hours=24" in SRC


def test_aucune_valeur_de_cookie_affichee():
    assert "c.value" not in SRC and ".value)" not in SRC.split("function rendreCookies")[1].split("function btn")[0]


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW_MS = int(time.time() * 1000)
STATUS = {"enabled": True, "running": True, "last_scan": None, "total_cookies": 4, "total_domains": 2, "third_party_cookies": 1, "tracker_cookies": 2,
          "violations_today": 3, "gdpr_mode": True, "tracker_detection": True}
STATS = {"success": True, "stats": {"total_cookies": 4, "total_domains": 2, "third_party_cookies": 1, "tracker_cookies": 2, "violations_today": 3,
                                    "tracker_categories": {"analytics": 1, "advertising": 1}},
         "config": {"gdpr_mode": True, "tracker_detection": True, "third_party_detection": False}}
COOKIES = {"success": True, "count": 2, "cookies": [
    {"domain": "www.example.com", "name": "_ga", "is_tracker": True, "tracker_name": "Exemple Analytics", "tracker_category": "analytics", "is_third_party": True, "last_seen": NOW_MS - 60000, "count": 7, "has_value": False},
    {"domain": "blog.example.org", "name": "<img src=x onerror=window.PWNED=1>", "is_tracker": False, "is_third_party": False, "last_seen": NOW_MS - 3600000, "count": 2, "has_value": False}]}
TRACKERS = {"success": True, "count": 1, "trackers": [{"name": "Exemple Analytics", "category": "analytics", "pattern": ".*analytics\\.example\\.net.*", "detections": 1}]}
POLICIES = {"success": True, "policies": [{"id": "pol1", "name": "RGPD", "enabled": True, "block_third_party": False, "block_trackers": True, "require_consent": True, "max_cookie_age_days": 365}]}
VIOL = {"success": True, "count": 1, "total": 1, "violations": [{"id": "v1", "timestamp": "2026-10-13T08:00:00", "policy": "RGPD", "domain": "www.example.com", "cookie_name": "_ga",
                                                                "violation_type": "tracker", "description": "Cookie traqueur détecté : Exemple Analytics"}]}
CONFIG = {"enabled": True, "gdpr_mode": True, "tracker_detection": True, "third_party_detection": False, "block_trackers": True, "alert_on_suspicious": True, "scan_interval": 600, "retention_days": 30}
XSITE = {"trackers": [{"tracker_domain": "regie.example.org", "site_count": 3, "client_count": 2, "cookie_count": 4, "pre_consent_hits": 5, "last_seen": int(time.time()) - 100, "sites": ["a.example.com", "b.example.net"]}]}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/cookies": (200, COOKIES), "/trackers": (200, TRACKERS), "/policies": (200, POLICIES),
       "/violations": (200, VIOL), "/config": (200, CONFIG)}


def ouvre(navigateur, url, routes, taille=None, xsite=(200, XSITE)):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "cookies":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/cookies", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/cookies/**", api)
    p.route("http://sbx.test/api/v1/toolbox/admin/cookie-crosssite**", lambda r, *_: r.fulfill(status=xsite[0], content_type="application/json", body=json.dumps(xsite[1])))
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cookies/", API)
    p.wait_for_selector("#bCook tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tTiers", "#tTrack", "#tDom", "#tViol")] == ["4", "1", "2", "2", "3"]
    assert p.inner_text("#etat") == "ACTIF"
    assert "_ga" in p.inner_text("#bCook") and "Exemple Analytics" in p.inner_text("#bCook") and "il y a" in p.inner_text("#bCook")
    assert "Expires" not in p.inner_text("#bCook") and "Session" not in p.inner_text("#bCook")   # l'ingest n'a pas d'expiration
    # détection des tiers : lue dans /stats.config (le /status ne la porte pas), donc « Inactif » ici
    assert p.inner_text("#sTiers") == "Inactif" and p.inner_text("#sGdpr") == "Activé"
    assert "TRAQUEUR" in p.inner_text("#violRecentes") and "regie.example.org" in p.inner_text("#bXs")
    assert err == []
    ctx.close()


def test_noms_de_cookies_hostiles_restent_du_texte(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cookies/", API)
    p.wait_for_selector("#bCook tr td.mono", state="attached")
    assert "onerror" in p.inner_text("#bCook") and p.evaluate("window.PWNED") is None
    assert p.locator("#bCook img").count() == 0 and err == []
    ctx.close()


def test_onglets_filtre_serveur_et_reglages(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cookies/", API)
    p.wait_for_selector("#bCook tr", state="attached")
    p.click("#o-traqueurs")
    assert p.get_attribute("#o-traqueurs", "aria-selected") == "true" and p.is_visible("#t-traqueurs") and not p.is_visible("#t-cookies")
    assert "Exemple Analytics" in p.inner_text("#bTr")
    p.click("#o-cookies"); p.select_option("#fCook", "trackers")
    p.wait_for_timeout(300)
    assert any(a[0] == "GET" and a[1] == "/cookies" for a in appels)
    p.click("#o-reglages")
    assert p.input_value("#cfg-scan_interval") == "600" and not p.is_checked("#cfg-third_party_detection")
    assert err == []
    ctx.close()


def test_reglage_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cookies/", API)
    p.click("#o-reglages"); p.wait_for_selector("#cfg-gdpr_mode")
    p.uncheck("#cfg-gdpr_mode")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('mise à jour')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/config"][0][2]) == {"gdpr_mode": False}
    p.fill("#cfg-scan_interval", "900"); p.press("#cfg-scan_interval", "Tab")
    p.wait_for_timeout(200)
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/config"][-1][2]) == {"scan_interval": 900}
    assert err == []
    ctx.close()


def test_retirer_un_motif_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cookies/", {**API, "/tracker/Exemple%20Analytics": (200, {"success": True})})
    p.click("#o-traqueurs"); p.wait_for_selector("#bTr tr td.act")
    p.locator("#bTr tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bTr tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rTr').textContent.includes('retiré')")
    assert ("DELETE", "/tracker/Exemple%20Analytics", None) in appels and err == []
    ctx.close()


def test_ajout_motif_politique_et_analyse_envoient_les_memes_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cookies/", API)
    p.click("#o-traqueurs"); p.click("#addTr")
    p.fill("#fTr [name=name]", "Test"); p.fill("#fTr [name=pattern]", ".*t\\.example\\.net.*"); p.select_option("#fTr [name=category]", "social")
    p.click("#fTr button[type=submit]")
    p.wait_for_function("document.getElementById('rTr').textContent.includes('ajouté')")
    assert json.loads([a for a in appels if a[1] == "/tracker/add"][0][2]) == {"name": "Test", "pattern": ".*t\\.example\\.net.*", "category": "social"}
    p.click("#o-politiques"); p.click("#addPol"); p.fill("#fPol [name=name]", "Stricte"); p.check("#fPol [name=tiers]"); p.click("#fPol button[type=submit]")
    p.wait_for_function("document.getElementById('rPol').textContent.includes('créée')")
    assert json.loads([a for a in appels if a[1] == "/policy" and a[0] == "POST"][0][2]) == {
        "name": "Stricte", "block_third_party": True, "block_trackers": True, "require_consent": True, "max_cookie_age_days": 365}
    p.locator("#bPol tr").first.get_by_text("Supprimer").click()
    p.locator("#bPol tr").first.get_by_text("Confirmer").click()
    p.wait_for_timeout(200)
    assert ("DELETE", "/policy/pol1", None) in appels
    p.click("#btnScan"); p.fill("#fScan [name=url]", "example.com"); p.click("#fScan button[type=submit]")
    p.wait_for_function("document.getElementById('retourGlobal').textContent.includes('Analyse terminée')")
    assert json.loads([a for a in appels if a[1] == "/scan"][0][2]) == {"url": "example.com", "include_third_party": True}
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cookies/", refus, xsite=(401, {}))
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tTiers", "#tTrack", "#tDom", "#tViol")] == ["—"] * 5
    assert p.url.startswith("http://sbx.test/cookies") and err == []     # plus de redirection vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cookies/?demo=1", {})
    p.wait_for_selector("#bCook tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tTotal") == "6"
    p.click("#o-traqueurs"); p.locator("#bTr tr").first.get_by_text("Retirer").click(); p.locator("#bTr tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rTr').textContent.includes('inerte')")
    p.click("#o-reglages"); p.click("#cfg-gdpr_mode")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cookies/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bCook tr td.mono", state="attached")
    for t in ("o-cookies", "o-traqueurs", "o-politiques", "o-violations", "o-reglages", "o-apercu"):
        p.click("#" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
