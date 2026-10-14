# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2647 — /saas-relay/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "saas-relay" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == []
    assert "/shared/sidebar.js" in SRC and "!EMB && !DEMO" in SRC
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'saas-relay'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_et_lecture_a_l_identique():
    for r in ("'POST', '/service/add'", "'DELETE', '/service/'", "'/toggle'", "'/check'", "'PUT', '/keys/'", "'DELETE', '/keys/'",
              "'DELETE', '/logs'", "'/status'", "'/services'", "'/keys'", "'/stats'", "'/logs'", "'/service/'", "?service="):
        assert r in SRC
    for champ in ("api_key", "service_type", "health_endpoint", "auth_header", "auth_prefix", "rate_limit", "quota_daily", "description"):
        assert champ in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer '" in SRC


def test_aucun_secret_stocke_ni_serie_inventee():
    assert "setItem" not in SRC and "Math.random" not in SRC
    assert 'id="sCle" type="password"' in SRC and 'id="kValeur" type="password"' in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
STATUS = {"services_count": 2, "enabled_count": 2, "total_requests": 1234, "requests_today": 56, "healthy_services": 1}
SERVICES = {"services": [
    {"name": "alpha", "display_name": "Alpha API", "base_url": "https://alpha.example.com", "service_type": "rest", "enabled": True, "health_status": "healthy"},
    {"name": "beta", "display_name": "Beta <b>x</b>", "base_url": "https://beta.example.com", "service_type": "graphql", "enabled": False, "health_status": "unknown"}]}
KEYS = {"keys": [{"service": "alpha", "display_name": "Alpha API", "has_key": True, "key_preview": "****wxyz"},
                 {"service": "beta", "display_name": "Beta", "has_key": False, "key_preview": None}]}
STATS = {"stats": [{"service": "alpha", "display_name": "Alpha API", "requests_today": 50, "requests_total": 900, "quota_daily": 100,
                    "quota_used_percent": 50.0, "avg_response_time_ms": 123.4, "error_rate": 6.0, "last_request": NOW},
                   {"service": "beta", "display_name": "Beta", "requests_today": 0, "requests_total": 0, "quota_daily": 10000,
                    "quota_used_percent": 0.0, "avg_response_time_ms": 0, "error_rate": 0, "last_request": None}]}
LOGS = {"logs": [{"timestamp": NOW, "service": "alpha", "method": "GET", "path": "/v1/x", "status_code": 200, "response_time_ms": 12.0},
                 {"timestamp": NOW, "service": "alpha", "method": "POST", "path": "/v1/y", "status_code": 502, "response_time_ms": 900.0}],
        "total": 2, "offset": 0, "limit": 100}
API = {"/status": (200, STATUS), "/services": (200, SERVICES), "/keys": (200, KEYS), "/stats": (200, STATS), "/logs": (200, LOGS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif"), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "saas-relay":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/saas-relay", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.url.split("?", 1)[1] if "?" in r.request.url else ""))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/saas-relay/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


URL = "http://sbx.test/saas-relay/"


def test_tuiles_et_services_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bServices tr td strong", state="attached")
    assert [p.inner_text(i) for i in ("#tServices", "#tActifs", "#tSains")] == ["2", "2", "1"]
    assert "56" in p.inner_text("#tJour") and p.inner_text("#etat") == "DÉGRADÉ"
    t = p.inner_text("#bServices")
    assert "Alpha API" in t and "GRAPHQL" in t and "Sain" in t and "Désactivé" in t
    assert "Beta <b>x</b>" in t and p.locator("#bServices b").count() == 0     # jamais interprété comme du HTML
    assert err == []
    ctx.close()


def test_onglets_cles_stats_journal(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bServices tr td strong", state="attached")
    p.click("#o-keys")
    p.wait_for_selector("#bKeys tr td .mono", state="attached")
    assert "****wxyz" in p.inner_text("#bKeys") and "Aucune clé" in p.inner_text("#bKeys")
    assert p.get_attribute("#o-keys", "aria-selected") == "true"
    p.click("#o-stats")
    p.wait_for_function("document.getElementById('bStats').textContent.includes('Alpha')")
    t = p.inner_text("#bStats")
    assert "123 ms" in t and "6,0 %" in t and "—" in t       # beta : aucune requête, pas de 0 ms
    p.click("#o-logs")
    p.wait_for_function("document.getElementById('bLogs').textContent.includes('/v1/x')")
    assert "502" in p.inner_text("#bLogs")
    assert ("GET", "/keys") in [(a[0], a[1]) for a in appels] and ("GET", "/stats") in [(a[0], a[1]) for a in appels]
    assert err == []
    ctx.close()


def test_ajouter_un_service_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bServices tr td strong", state="attached")
    p.click("#btnAjout")
    p.fill("#sNom", "gamma"); p.fill("#sAffiche", "Gamma"); p.fill("#sUrl", "https://g.example.com"); p.fill("#sCle", "secret-123")
    p.select_option("#sType", "webhook"); p.fill("#sLimite", "50"); p.fill("#sQuota", "500")
    p.click("#btnAjouter")
    p.wait_for_function("document.getElementById('pAjout').hidden")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/service/add"][0]
    assert json.loads(post[2]) == {"name": "gamma", "display_name": "Gamma", "base_url": "https://g.example.com", "api_key": "secret-123",
                                   "service_type": "webhook", "health_endpoint": None, "auth_header": "Authorization", "auth_prefix": "Bearer ",
                                   "rate_limit": 50, "quota_daily": 500, "description": None}
    assert p.input_value("#sCle") == ""
    ctx.close()


def test_basculer_controler_voir(navigateur):
    routes = {**API, "/service/alpha": (200, {"name": "alpha", "display_name": "Alpha API", "base_url": "https://alpha.example.com", "service_type": "rest",
                                              "auth_header": "Authorization", "rate_limit": 100, "quota_daily": 10000, "enabled": True, "has_api_key": True,
                                              "health_status": "healthy", "description": "d", "created_at": NOW}),
              "/service/alpha/check": (200, {"service": "alpha", "health": {"status": "degraded", "message": "lent"}})}
    ctx, p, err, appels = ouvre(navigateur, URL, routes)
    p.wait_for_selector("#bServices tr td strong", state="attached")
    ligne = p.locator("#bServices tr").first
    ligne.get_by_text("Voir").click()
    p.wait_for_selector("#detail:not([hidden])")
    assert "Alpha API" in p.inner_text("#dlDetail") and "Oui" in p.inner_text("#dlDetail")
    ligne.get_by_text("Désactiver").click()
    p.wait_for_timeout(300)
    ligne.get_by_text("Contrôler").click()
    p.wait_for_function("document.getElementById('rServices').textContent.includes('lent')")
    assert ("POST", "/service/alpha/toggle", None, "") in appels and ("POST", "/service/alpha/check", None, "") in appels
    assert err == []
    ctx.close()


def test_retrait_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bServices tr td strong", state="attached")
    p.locator("#bServices tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bServices tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bServices tr").first.get_by_text("Retirer").click()
    p.locator("#bServices tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rServices').textContent.includes('retiré')")
    assert ("DELETE", "/service/alpha", None, "") in appels and err == []
    ctx.close()


def test_mise_a_jour_et_suppression_de_cle(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.click("#o-keys")
    p.wait_for_selector("#bKeys tr td .mono", state="attached")
    p.locator("#bKeys tr").first.get_by_text("Mettre à jour").click()
    p.fill("#kValeur", "nouvelle-cle")
    p.click("#btnCle")
    p.wait_for_function("document.getElementById('pCle').hidden")
    assert ("PUT", "/keys/alpha", '{"api_key":"nouvelle-cle"}', "") in appels
    assert p.input_value("#kValeur") == ""
    p.locator("#bKeys tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bKeys tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rKeys').textContent.includes('supprimée')")
    assert ("DELETE", "/keys/alpha", None, "") in appels and err == []
    ctx.close()


def test_journal_filtre_et_vidage(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.click("#o-logs")
    p.wait_for_function("document.getElementById('bLogs').textContent.includes('/v1/x')")
    p.select_option("#filtre", "alpha")
    p.wait_for_timeout(300)
    p.click("#btnVide")
    p.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rLogs').textContent.includes('vidé')")
    assert ("GET", "/logs", None, "service=alpha") in appels and ("DELETE", "/logs", None, "service=alpha") in appels
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tServices", "#tActifs", "#tSains", "#tJour", "#tTotal")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#bServices tr td strong", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert not p.is_visible("#sidebar")
    p.locator("#bServices tr").first.get_by_text("Désactiver").click()
    p.wait_for_function("document.getElementById('rServices').textContent.includes('inerte')")
    p.click("#btnAjout"); p.fill("#sNom", "x"); p.fill("#sAffiche", "X"); p.fill("#sUrl", "https://x.example.com"); p.fill("#sCle", "k")
    p.click("#btnAjouter")
    p.wait_for_function("document.getElementById('rAjout').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_cas_vide(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bServices tr td strong", state="attached")
    for onglet in ("o-keys", "o-stats", "o-logs"):
        p.click("#" + onglet)
    p.click("#btnAjout")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, URL, {k: (503, {}) for k in API})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and p.inner_text("#tServices") == "—" and err == []
    ctx.close()
