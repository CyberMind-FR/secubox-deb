# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2650 — /cyberfeed/ au profil Aurora (composant de secubox-ipblock) : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "cyberfeed" / "www" / "cyberfeed" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for interdit in ("hybrid-dark", "crt-light", "confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "fonts.googleapis"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'cyberfeed'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer '" in SRC and "document.hidden" in SRC


def test_routes_a_l_identique():
    assert "const API = '/api/v1/cyberfeed'" in SRC
    for r in ("appel('/stats')", "appel('/feeds')", "'/blocklist/ips?limit=100'", "'/blocklist/domains?limit=100'", "'/indicators?limit=50'",
              "'/enable?enabled=' + actif, { method: 'POST' }", "'/update', { method: 'POST' }", "appel('/feeds/update', { method: 'POST' })",
              "'/feeds/' + encodeURIComponent(nom), { method: 'DELETE' }", "appel('/feeds/add', { method: 'POST', body: JSON.stringify(feed) })",
              "'/check/ip/'", "'/check/domain/'", "'/export/' + type + '?format=' + format"):
        assert r in SRC
    for c in ("name:", "url:", "feed_type:", "format:", "category:", "description:", "enabled: true"):
        assert c in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATS = {"total_feeds": 3, "active_feeds": 2, "total_ips": 1500, "total_domains": 40, "total_urls": 0, "feeds_with_errors": 1, "last_global_update": "2026-10-12T07:00:00Z"}
FEEDS = {"feeds": [
    {"name": "abuse-ch-feodo", "description": "Feodo <b>C2</b>", "feed_type": "ip", "category": "botnet", "enabled": True, "status": "active", "entry_count": 1500, "last_update": "2026-10-12T07:00:00Z", "builtin": True},
    {"name": "perso", "description": "Perso", "feed_type": "domain", "category": "malware", "enabled": True, "status": "error", "error": "HTTP 503", "entry_count": 40, "last_update": None, "builtin": False},
    {"name": "tor", "description": None, "feed_type": "ip", "category": None, "enabled": False, "status": "disabled", "entry_count": 0, "last_update": None, "builtin": True}]}
API = {"/stats": (200, STATS), "/feeds": (200, FEEDS),
       "/blocklist/ips": (200, {"total": 150, "ips": ["192.0.2.1", "192.0.2.2"]}),
       "/blocklist/domains": (200, {"total": 1, "domains": ["mal.exemple.test"]}),
       "/indicators": (200, {"indicators": [{"value": "192.0.2.1", "source": "abuse-ch-feodo", "category": "botnet", "ioc_type": "ip"}], "count": 1}),
       "/check/ip/192.0.2.1": (200, {"ip": "192.0.2.1", "blocked": True, "matches": [{"feed": "abuse-ch-feodo", "category": "botnet"}]}),
       "/check/domain/ok.exemple.test": (200, {"domain": "ok.exemple.test", "blocked": False, "matches": []}),
       "/export/ips": (200, {"format": "nftables", "count": 2, "content": "define CYBERFEED_IPS = {\n 192.0.2.1,\n}\n"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "cyberfeed":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/cyberfeed", 1)[1].split("?")[0]
        appels.append((r.request.method, r.request.url.split("/api/v1/cyberfeed", 1)[1], r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method != "GET":
            statut, corps = routes.get(chemin, (200, {"success": True}))
        else:
            statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/cyberfeed/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cyberfeed/", API)
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    assert [p.inner_text(i) for i in ("#tFlux", "#tErr")] == ["2", "1"]
    assert p.inner_text("#tIp").replace(" ", " ").replace("\xa0", " ") == "1 500"
    assert p.inner_text("#etat") == "1 FLUX EN ERREUR"
    t = p.inner_text("#bFlux")
    assert "abuse-ch-feodo" in t and "Feodo <b>C2</b>" in t          # affiché comme texte, jamais interprété
    assert p.locator("#bFlux b").count() == 0
    assert p.locator("#bFlux tr").nth(1).locator("td").nth(5).locator(".pill").get_attribute("title") == "HTTP 503"
    assert p.locator("#bFlux tr").nth(2).locator("td").nth(3).inner_text() == "—"
    assert p.locator("#bFlux tr").nth(0).get_by_text("Retirer").count() == 0     # flux intégré : pas de retrait
    assert err == []
    ctx.close()


def test_filtre_cote_client(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/cyberfeed/", API)
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    p.fill("#filtre", "malware")
    assert p.locator("#bFlux tr").count() == 1 and "perso" in p.inner_text("#bFlux")
    ctx.close()


def test_activer_un_flux_envoie_le_meme_appel(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cyberfeed/", API)
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    p.locator("#bFlux tr").nth(2).locator("input[type=checkbox]").check(force=True)
    p.wait_for_timeout(300)
    assert ("POST", "/feed/tor/enable?enabled=true", None) in [a[:3] for a in appels]
    ctx.close()


def test_mettre_a_jour_un_flux_et_tous(navigateur):
    routes = {**API, "/feed/perso/update": (400, {"detail": "HTTP 503 du flux"}), "/feed/abuse-ch-feodo/update": (200, {"success": True, "entries": 1500}),
              "/feeds/update": (200, {"results": [{"success": True}, {"success": False}]})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cyberfeed/", routes)
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    p.locator("#bFlux tr").nth(1).get_by_text("Mettre à jour").click()
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('HTTP 503 du flux')")      # le motif de l'API est affiché
    p.locator("#bFlux tr").nth(0).get_by_text("Mettre à jour").click()
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('mis à jour : ')")
    p.click("#majTout")
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('1 flux mis à jour, 1 en échec')")
    assert ("POST", "/feeds/update", None) in [a[:3] for a in appels] and err == []
    ctx.close()


def test_retrait_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cyberfeed/", API)
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    p.locator("#bFlux tr").nth(1).get_by_text("Retirer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bFlux tr").nth(1).get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bFlux tr").nth(1).get_by_text("Retirer").click()
    p.locator("#bFlux tr").nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('retiré')")
    assert ("DELETE", "/feeds/perso", None) in [a[:3] for a in appels]
    ctx.close()


def test_ajouter_un_flux_envoie_le_meme_corps_et_l_entete_bearer(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cyberfeed/", {**API, "/feeds/add": (200, {"success": True})})
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    p.click("#ajouter")
    p.click("#btnAjout")                                                 # champs vides : refus local
    assert "obligatoires" in p.inner_text("#rFlux") and not [a for a in appels if a[1] == "/feeds/add"]
    p.fill("#fNom", "mon-flux"); p.fill("#fUrl", "https://exemple.test/l.txt"); p.select_option("#fType", "domain"); p.select_option("#fFormat", "hosts"); p.fill("#fCat", "spam")
    p.click("#btnAjout")
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/feeds/add"][0]
    assert json.loads(post[2]) == {"name": "mon-flux", "url": "https://exemple.test/l.txt", "feed_type": "domain", "format": "hosts",
                                    "category": "spam", "description": None, "enabled": True}
    assert post[3] == "Bearer jeton-test"
    ctx.close()


def test_listes_verification_et_export(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cyberfeed/", API)
    p.click("#o-listes")
    p.wait_for_function("document.getElementById('lIp').textContent.includes('192.0.2.2')")
    assert "150 au total" in p.inner_text("#nIp") and "mal.exemple.test" in p.inner_text("#lDom") and "… et 148 autres" in p.inner_text("#lIp")
    p.click("#o-verif")
    p.wait_for_selector("#lIoc .ioc", state="attached")
    p.fill("#verif", "192.0.2.1"); p.click("#btnVerif")
    p.wait_for_selector("#resVerif.ko")
    assert "BLOQUÉ" in p.inner_text("#resVerif") and "abuse-ch-feodo" in p.inner_text("#resVerif")
    p.fill("#verif", "ok.exemple.test"); p.click("#btnVerif")
    p.wait_for_selector("#resVerif.ok")
    assert "SAIN" in p.inner_text("#resVerif")
    p.click("#o-export")
    p.click("[data-ex='ips:nftables']")
    p.wait_for_selector("#apercu:not([hidden])")
    assert "CYBERFEED_IPS" in p.inner_text("#contenu")
    assert ("GET", "/export/ips?format=nftables") in [a[:2] for a in appels] and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cyberfeed/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tFlux", "#tIp", "#tDom", "#tErr", "#tMaj")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cyberfeed/?demo=1", {})
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#majTout")
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('inerte')")
    p.locator("#bFlux tr").nth(1).get_by_text("Mettre à jour").click()
    p.locator("#bFlux tr").nth(1).get_by_text("Retirer").click()
    p.locator("#bFlux tr").nth(1).get_by_text("Confirmer").click()
    p.locator("#bFlux tr").nth(2).locator("input[type=checkbox]").first.click(force=True)
    p.click("#o-listes"); p.click("#o-verif"); p.click("#o-export"); p.click("[data-ex='ips:plain']")
    p.wait_for_selector("#apercu:not([hidden])")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cyberfeed/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bFlux tr td .pill", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    for o in ("#o-listes", "#o-verif", "#o-export"):
        p.click(o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
