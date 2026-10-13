# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /certs/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "certs" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-skin" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange=", "oninput="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower() and "simulated" not in SRC.lower() and "Math.random" not in SRC
    assert "sbxVue" in SRC and "onglet: 'certs'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("ecrire('POST', '/check', corps)", "ecrire('POST', '/issue', corps)", "ecrire('POST', '/renew/' + encodeURIComponent(domaine))",
              "ecrire('POST', '/renew-all')", "ecrire('DELETE', '/revoke/' + encodeURIComponent(domaine))", "lire('/list')", "lire('/metrics')"):
        assert r in SRC
    for cle in ("domain:", "dns_provider:", "backend_type:", "backend_port:"):
        assert cle in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def cert(domain, days, **kw):
    st = "unknown" if days is None else "expired" if days < 0 else "critical" if days <= 7 else "warning" if days <= 30 else "healthy"
    return {"domain": domain, "file": domain + ".pem", "expiry": None if days is None else "2026-12-01T10:00:00", "days": days, "status": st,
            "origin_emoji": "🌐", "origin_name": kw.get("origin", "Web"), "issuer": kw.get("issuer", "Let's Encrypt R11"), "size": 5120, "modified": "2026-10-01T08:00:00"}


LISTE = {"certificates": [cert("a.example.org", 90), cert("b.example.org", 12, origin="Gitea"), cert("c.example.org", 5), cert("d.example.org", -3),
                          cert("e.example.org", None, issuer="Unknown")], "summary": {}}
METR = {"domains": [{"domain": "b.example.org", "attacks_total": 1245, "attacks_today": 31}, {"domain": "a.example.org", "attacks_total": 7, "attacks_today": 0}],
        "summary": {"total_attacks": 1252, "today_attacks": 31, "blocked_ips": 9, "top_categories": {"Injection SQL": 40, "Balayage": 12}, "total_visits": 5000, "today_visits": 123}}
API = {"/list": (200, LISTE), "/metrics": (200, METR)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "certs":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/certs", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/certs/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/certs/", API)
    p.wait_for_selector("#bCerts tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tExpires", "#tCritiques", "#tSurveiller", "#tSains", "#tInconnus", "#tTotal", "#tAttaques")] == ["1", "1", "1", "1", "1", "5", "31"]
    assert p.inner_text("#etat") == "EN LIGNE"
    t = p.inner_text("#bCerts")
    assert "il y a 3 j" in t and "illisible" in t and "1 245" in t.replace(" ", " ").replace("\xa0", " ")
    assert "ILLISIBLE" in t and "EXPIRÉ" in t
    # un certificat illisible n'est jamais « expiré » ; son émetteur « Unknown » devient un tiret
    p.click("#o-expires"); assert p.locator("#bCerts tr").count() == 1 and "d.example.org" in p.inner_text("#bCerts")
    p.click("#o-inconnus"); assert p.locator("#bCerts tr").count() == 1 and "e.example.org" in p.inner_text("#bCerts")
    p.click("#o-bientot"); assert p.locator("#bCerts tr").count() == 2
    p.click("#o-metriques"); assert p.is_visible("#t-metriques") and not p.is_visible("#t-certs") and p.inner_text("#mIps") == "9"
    p.click("#o-attaques"); assert "Injection SQL" in p.inner_text("#topCategories") and "b.example.org" in p.inner_text("#topCibles")
    assert err == []
    ctx.close()


def test_renouveler_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/certs/", {**API, "/renew/b.example.org": (200, {"success": True})})
    p.wait_for_selector("#bCerts tr td.mono", state="attached")
    p.locator("#bCerts tr", has_text="b.example.org").get_by_text("Renouveler").click()
    assert p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]      # pas encore : il faut confirmer
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Renouvelé')")
    assert ("POST", "/renew/b.example.org", None) in appels
    # annuler n'envoie rien
    p.locator("#bCerts tr", has_text="a.example.org").get_by_text("Renouveler").click(); p.click("#confNon")
    assert not p.is_visible("#conf") and all(a[1] != "/renew/a.example.org" for a in appels)
    assert err == []
    ctx.close()


def test_renouvellement_groupe_et_revocation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/certs/", {**API, "/renew-all": (200, {"processed": 3, "results": [{"domain": "b", "success": True}, {"domain": "c", "success": False, "error": "boum"}]}),
                                                                     "/revoke/d.example.org": (200, {"success": True})})
    p.wait_for_selector("#bCerts tr td.mono", state="attached")
    p.click("#renouvelleTout"); assert "3 certificats" in p.inner_text("#confTexte")     # 12 j, 5 j, -3 j ; l'illisible est ignoré
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('en échec')")
    assert ("POST", "/renew-all", None) in appels and "boum" in p.inner_text("#retour")
    p.locator("#bCerts tr", has_text="d.example.org").get_by_text("Détails").click()
    assert p.is_visible("#detail") and p.inner_text("#dEtat") == "EXPIRÉ"
    p.click("#dRevoque"); assert "irréversible" in p.inner_text("#confTexte") and not [a for a in appels if a[0] == "DELETE"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Révoqué')")
    assert ("DELETE", "/revoke/d.example.org", None) in appels
    ctx.close()


def test_assistant_envoie_le_meme_corps_et_bloque_si_verification_echoue(navigateur):
    ok = {"checks": [{"name": "DNS Resolution", "pass": True, "msg": "Resolved to IP"}], "ready": True}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/certs/", {**API, "/check": (200, ok), "/issue": (200, {"success": True, "cert_file": "/data/haproxy/certs/n.example.org.pem"})})
    p.click("#nouveau"); p.fill("#wDomaine", "n.example.org"); p.select_option("#wService", "gitea"); p.select_option("#wDns", "http")
    assert p.input_value("#wPort") == "3000"
    p.click("#wVerifier"); p.wait_for_selector("#wVerifs .verif")
    assert json.loads([a for a in appels if a[1] == "/check"][0][2]) == {"domain": "n.example.org", "dns_provider": "http", "backend_type": "gitea", "backend_port": 3000}
    p.wait_for_function("!document.getElementById('wEmettre').disabled")
    p.click("#wEmettre"); p.wait_for_selector("#etape3:not([hidden])")
    assert "n.example.org.pem" in p.inner_text("#wResultat") and ("POST", "/issue") in [(a[0], a[1]) for a in appels]
    ctx.close()
    # réponse d'erreur (403) : aucune émission possible (l'ancienne page l'autorisait)
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/certs/", {**API, "/check": (403, {"detail": "Admin requis"})})
    p.click("#nouveau"); p.fill("#wDomaine", "n.example.org"); p.click("#wVerifier")
    p.wait_for_selector("#wVerifs .retour.ko")
    assert p.is_disabled("#wEmettre") and "Admin requis" in p.inner_text("#wVerifs")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/certs/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tExpires", "#tCritiques", "#tSains", "#tTotal", "#tAttaques")] == ["—"] * 5 and err == []
    ctx.close()


def test_metriques_en_panne_pas_de_zero_invente(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/certs/", {"/list": (200, LISTE)})
    p.wait_for_selector("#bCerts tr td.mono", state="attached")
    assert p.inner_text("#tAttaques") == "—" and p.is_visible("#erreur") and "—" in p.inner_text("#bCerts tr:first-child td:nth-child(7)") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/certs/?demo=1", {})
    p.wait_for_selector("#bCerts tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bCerts tr").first.get_by_text("Renouveler").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/certs/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bCerts tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
