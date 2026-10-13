# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /dns/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "dns" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'dns'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "window.location" not in SRC  # plus de redirection brutale sur 401 : bandeau « session requise »


def test_routes_a_l_identique_de_l_ancienne_page():
    for r in ("'/status'", "'/zones'", "/records'", "'POST', '/record'", "'DELETE', '/record'", "'POST', '/zone'", "'POST', '/reload'", "sbx_token"):
        assert r in SRC
    # corps d'ajout / suppression d'enregistrement inchangés
    assert "{ zone: ZONE, type: f.type.value, name:" in SRC and "{ zone: ZONE, type: r.type, name: r.name, value: r.value }" in SRC
    assert "{ name: f.name.value.trim() }" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"running": True, "zones": 2, "records": 3, "default_ttl": 3600}
ZONES = {"zones": [{"name": "example.com", "records": 3, "valid": True}, {"name": "example.net", "records": 0, "valid": False}]}
RECS = {"records": [{"type": "A", "name": "@", "value": "192.0.2.10", "ttl": 300},
                    {"type": "TXT", "name": "t", "value": 'v=spf1 "x" <b>y</b>', "ttl": 60},
                    {"type": "MX", "name": "@", "value": "10 mail.example.com.", "ttl": None}]}
API = {"GET /status": (200, STATUS), "GET /zones": (200, ZONES), "GET /zone/example.com/records": (200, RECS), "GET /zone/example.net/records": (200, {"records": []})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "dns":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/dns", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(r.request.method + " " + chemin, (200, {"success": True, "output": "ok"}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/dns/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_zones_et_enregistrements_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/dns/", API)
    p.wait_for_selector("#listeZones button")
    assert [p.inner_text(i) for i in ("#tBind", "#tZones", "#tRecs", "#tTtl")] == ["Actif", "2", "3", "3600 s"]
    assert p.inner_text("#etat") == "BIND ACTIF" and "INVALIDE" in p.inner_text("#listeZones")
    p.click("#listeZones button >> text=example.com")
    p.wait_for_selector("#bRecs td.mono")
    txt = p.inner_text("#bRecs")
    assert "192.0.2.10" in txt and "<b>y</b>" in txt  # valeur d'API affichée comme texte, jamais interprétée
    assert p.locator("#bRecs b").count() == 0
    p.click("#filtres button >> text=TXT")
    assert p.locator("#bRecs tr").count() == 1
    assert err == []
    ctx.close()


def test_ttl_absent_est_un_tiret(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/dns/", {**API, "GET /status": (200, {"running": True, "zones": 2})})
    p.wait_for_selector("#listeZones button")
    assert p.inner_text("#tTtl") == "—" and p.inner_text("#tRecs") == "—"
    ctx.close()


def test_supprimer_demande_confirmation_dans_la_page_et_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/dns/", API)
    p.click("#listeZones button >> text=example.com"); p.wait_for_selector("#bRecs td.act")
    p.locator("#bRecs tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bRecs tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRecs').textContent.includes('supprimé')")
    d = [a for a in appels if a[0] == "DELETE"][0]
    assert d[1] == "/record" and json.loads(d[2]) == {"zone": "example.com", "type": "A", "name": "@", "value": "192.0.2.10"}
    ctx.close()


def test_ajout_enregistrement_et_zone_corps_identiques(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/dns/", API)
    p.click("#listeZones button >> text=example.com"); p.wait_for_selector("#bRecs td.mono")
    p.click("#addRec"); p.fill("#fRec [name=name]", "www"); p.fill("#fRec [name=value]", "198.51.100.5"); p.fill("#fRec [name=ttl]", "600")
    p.click("#fRec button[type=submit]")
    p.wait_for_function("document.getElementById('rRecs').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/record"][0]
    assert json.loads(post[2]) == {"zone": "example.com", "type": "A", "name": "www", "value": "198.51.100.5", "ttl": 600}
    p.click("#addZone"); p.fill("#fZone [name=name]", "exemple.org"); p.click("#fZone button[type=submit]")
    p.wait_for_function("document.getElementById('rZones').textContent.includes('créée')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/zone"][0][2]) == {"name": "exemple.org"}
    ctx.close()


def test_echec_dnsmaster_est_affiche(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/dns/", {**API, "POST /zone": (200, {"success": False, "output": "zone existe deja"})})
    p.wait_for_selector("#listeZones button")
    p.click("#addZone"); p.fill("#fZone [name=name]", "example.com"); p.click("#fZone button[type=submit]")
    p.wait_for_function("document.getElementById('rZones').textContent.includes('zone existe')")
    ctx.close()


def test_recharger_bind_confirmation_puis_post(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/dns/", API)
    p.wait_for_selector("#listeZones button")
    p.click("#recharge")
    assert not [a for a in appels if a[1] == "/reload"]
    p.locator("#cRecharge").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('rechargé')")
    assert ("POST", "/reload", None) in appels
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/dns/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tBind", "#tZones", "#tRecs", "#tTtl")] == ["—"] * 4 and err == []
    assert p.url == "http://sbx.test/dns/"  # pas de redirection
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/dns/?demo=1", {})
    p.wait_for_selector("#listeZones button")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#listeZones button").first.click(); p.wait_for_selector("#bRecs td.act")
    p.locator("#bRecs tr").first.get_by_text("Supprimer").click(); p.locator("#bRecs tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRecs').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/dns/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#listeZones button")
    p.click("#listeZones button >> text=example.com"); p.wait_for_selector("#bRecs td.mono")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
