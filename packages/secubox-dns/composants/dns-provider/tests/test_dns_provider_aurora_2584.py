# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /dns-provider/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "dns-provider" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "crt-engine" not in SRC and "hybrid-dark" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "window.location"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'dns-provider'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique_de_l_ancienne_page():
    for r in ("'/summary'", "'/providers'", "'/domains'", "'/config'", "/logs?limit=50", "sbx_token",
              "'POST', '/provider', { provider: type, name, credentials, enabled: true }",
              "'PUT', '/provider/' + encodeURIComponent(p.id), { enabled: !p.enabled }",
              "'DELETE', '/provider/' +",
              "'POST', '/domain/' + encodeURIComponent(SEL.name) + '/record?provider_id='",
              "'DELETE', '/domain/' + encodeURIComponent(SEL.name) + '/record/'",
              "'/acme/challenge?provider_id='", "{ domain, token, key_authorization: keyauth }",
              "'DELETE', '/acme/challenge?domain='", "'/ddns/update?provider_id='", "{ domain, subdomain }",
              "'POST', '/config', cfg"):
        assert r in SRC, r
    assert "localStorage.setItem" not in SRC  # aucun secret (ni autre chose) conservé côté navigateur


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


SUMMARY = {"providers": {"total": 2, "active": 1, "by_type": {"gandi": 1, "cloudflare": 1}}, "domains": 0}
PROVIDERS = {"providers": [
    {"id": "p1", "name": "Gandi test", "provider": "gandi", "enabled": True, "credentials": {"api_key": "SECR****"}, "created_at": "2026-10-01T10:00:00"},
    {"id": "p2", "name": "Cloudflare test", "provider": "cloudflare", "enabled": False, "credentials": {"api_token": "SECR****"}, "created_at": "2026-10-02T10:00:00"}]}
DOMAINS = {"domains": [{"name": "example.com", "status": "active", "provider_id": "p1", "provider_name": "Gandi test", "provider_type": "gandi"},
                       {"provider_id": "p9", "provider_name": "OVH casse", "provider_type": "ovh", "error": "OVH API error: 403"}]}
RECS = {"domain": "example.com", "provider_id": "p1", "records": [
    {"id": "www_A", "type": "A", "name": "www", "value": "192.0.2.10", "ttl": 300},
    {"id": "t_TXT", "type": "TXT", "name": "t", "value": "v=spf1 'x' <b>y</b>", "ttl": 60}]}
CONFIG = {"default_ttl": 300, "acme_ttl": 60, "ddns_check_interval": 600, "audit_retention_days": 90}
LOGS = {"logs": [{"timestamp": "2026-10-13T08:00:00", "action": "ddns_update", "user": "admin", "details": {"domain": "example.com", "subdomain": "box", "ip": "198.51.100.7", "action": "updated"}},
                 {"timestamp": "2026-10-13T07:00:00", "action": "acme_challenge_created", "user": "admin", "details": {"domain": "example.com"}}], "total": 2}
API = {"GET /summary": (200, SUMMARY), "GET /providers": (200, PROVIDERS), "GET /domains": (200, DOMAINS), "GET /config": (200, CONFIG),
       "GET /logs": (200, LOGS), "GET /domain/example.com/records": (200, RECS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, dialogues = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (dialogues.append(d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "dns-provider":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        reste = r.request.url.split("/api/v1/dns-provider", 1)[1]
        chemin = reste.split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, reste))
        cle = r.request.method + " " + chemin
        statut, corps = routes.get(cle, (200, {"success": True}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/dns-provider/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels, dialogues


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", API)
    p.wait_for_selector("#bFourn tr td.mono", state="attached")
    # 1 domaine réel : l'entrée en erreur n'est pas comptée comme domaine
    assert [p.inner_text(i) for i in ("#tFourn", "#tDom", "#tEnr", "#tEtat")] == ["2", "1", "—", "OK"]
    assert p.inner_text("#etat") == "FOURNISSEUR ACTIF"
    t = p.inner_text("#bFourn")
    assert "Gandi test" in t and "DÉSACTIVÉ" in t and "SECR" not in p.content()   # identifiants masqués non affichés
    p.click("#o-domaines")
    assert "example.com" in p.inner_text("#bDom") and "OVH casse" in p.inner_text("#alertesDom") and "undefined" not in p.inner_text("#t-domaines")
    assert "10.0" not in p.inner_text("#tEnr")
    p.click("#o-reglages")
    assert p.input_value("#fConf [name=ddns_check_interval]") == "600" and "ddns_update" in p.inner_text("#bLog")
    p.click("#o-ddns")
    assert "box.example.com" in p.inner_text("#bDdnsJ") and "198.51.100.7" in p.inner_text("#bDdnsJ")
    assert err == []
    ctx.close()


def test_enregistrements_valeur_hostile_comme_texte_et_compte(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", API)
    p.wait_for_selector("#bFourn tr td.mono", state="attached")
    p.click("#o-enregistrements"); p.click("#lDom button")
    p.wait_for_selector("#bEnr td.mono")
    assert "<b>y</b>" in p.inner_text("#bEnr") and p.locator("#bEnr b").count() == 0
    assert p.inner_text("#tEnr") == "2" and p.inner_text("#sEnr") == "example.com"
    assert any(a[3] == "/domain/example.com/records?provider_id=p1" for a in appels)
    p.fill("#rechEnr", "txt")
    assert p.locator("#bEnr tr").count() == 1
    assert err == []
    ctx.close()


def test_supprimer_enregistrement_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels, dial = ouvre(navigateur, "http://sbx.test/dns-provider/", {**API, "DELETE /domain/example.com/record/www_A": (200, {"success": True})})
    p.click("#o-enregistrements"); p.wait_for_selector("#lDom button"); p.click("#lDom button"); p.wait_for_selector("#bEnr td.act")
    p.locator("#bEnr tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]          # pas encore : il faut confirmer
    p.locator("#bEnr tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rEnr').textContent.includes('supprimé')")
    d = [a for a in appels if a[0] == "DELETE"][0]
    assert d[3] == "/domain/example.com/record/www_A?provider_id=p1" and d[2] is None and dial == []
    ctx.close()


def test_suppression_qui_echoue_est_dite(navigateur):
    ctx, p, _, _, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", {**API, "DELETE /domain/example.com/record/www_A": (200, {"success": False})})
    p.click("#o-enregistrements"); p.wait_for_selector("#lDom button"); p.click("#lDom button"); p.wait_for_selector("#bEnr td.act")
    p.locator("#bEnr tr").first.get_by_text("Supprimer").click(); p.locator("#bEnr tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rEnr').textContent.includes('impossible')")
    ctx.close()


def test_ajout_enregistrement_corps_identique(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", API)
    p.click("#o-enregistrements"); p.wait_for_selector("#lDom button"); p.click("#lDom button"); p.wait_for_selector("#bEnr td.mono")
    p.click("#addEnr"); p.select_option("#fEnr [name=type]", "MX"); p.fill("#fEnr [name=name]", "www"); p.fill("#fEnr [name=value]", "mail.example.com.")
    p.fill("#fEnr [name=ttl]", "600"); p.fill("#fEnr [name=priority]", "10")
    p.click("#fEnr button[type=submit]")
    p.wait_for_function("document.getElementById('rEnr').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[3] == "/domain/example.com/record?provider_id=p1"
    assert json.loads(post[2]) == {"type": "MX", "name": "www", "value": "mail.example.com.", "ttl": 600, "priority": 10}
    ctx.close()


def test_ajout_fournisseur_envoie_les_identifiants_puis_les_vide(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", {**API, "POST /provider": (200, {"success": True, "id": "p3"})})
    p.wait_for_selector("#bFourn tr td.mono", state="attached")
    p.click("#addFourn"); p.fill("#fFourn [name=name]", "Mon Gandi")
    assert p.get_attribute("#fFourn [data-cred=api_key]", "type") == "password"
    p.fill("#fFourn [data-cred=api_key]", "cle-secrete-xyz")
    p.click("#fFourn button[type=submit]")
    p.wait_for_function("/ajouté|Enregistré|domaine/.test(document.getElementById('rFourn').textContent)")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/provider"][0]
    assert json.loads(post[2]) == {"provider": "gandi", "name": "Mon Gandi", "credentials": {"api_key": "cle-secrete-xyz"}, "enabled": True}
    assert "cle-secrete-xyz" not in p.content() and p.evaluate("[...document.querySelectorAll('input')].every(i => !i.value.includes('cle-secrete'))")
    assert p.evaluate("Object.keys(localStorage).length") == 0 and err == []
    ctx.close()


def test_fournisseur_basculer_et_supprimer(navigateur):
    ctx, p, _, appels, dial = ouvre(navigateur, "http://sbx.test/dns-provider/", API)
    p.wait_for_selector("#bFourn tr td.act")
    p.locator("#bFourn tr").nth(1).get_by_text("Activer").click()
    p.wait_for_function("document.getElementById('rFourn').textContent.includes('activé')")
    put = [a for a in appels if a[0] == "PUT"][0]
    assert put[1] == "/provider/p2" and json.loads(put[2]) == {"enabled": True}
    p.locator("#bFourn tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bFourn tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rFourn').textContent.includes('supprimé')")
    assert ("DELETE", "/provider/p1", None) in [a[:3] for a in appels] and dial == []
    ctx.close()


def test_acme_ddns_et_config_corps_identiques(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", {**API, "POST /acme/challenge": (200, {"success": True, "record": "_acme-challenge.example.com"}),
        "POST /ddns/update": (200, {"success": True, "domain": "example.com", "subdomain": "box", "ipv4": "198.51.100.7", "action": "created"})})
    p.wait_for_selector("#bFourn tr td.mono", state="attached")
    p.click("#o-acme"); p.fill("#fAcme [name=domain]", "example.com"); p.fill("#fAcme [name=token]", "tok1"); p.fill("#fAcme [name=keyauth]", "ka1")
    p.click("#fAcme button[type=submit]")
    p.wait_for_function("document.getElementById('rAcme').textContent.includes('_acme-challenge')")
    a = [x for x in appels if x[1] == "/acme/challenge" and x[0] == "POST"][0]
    assert a[3] == "/acme/challenge?provider_id=p1" and json.loads(a[2]) == {"domain": "example.com", "token": "tok1", "key_authorization": "ka1"}
    p.fill("#fAcme [name=keyauth]", "ka1")
    p.locator("#cAcme").get_by_text("Supprimer le défi").click()
    assert not [x for x in appels if x[0] == "DELETE"]
    p.locator("#cAcme").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rAcme').textContent.includes('Défi supprimé')")
    assert [x for x in appels if x[0] == "DELETE"][0][3] == "/acme/challenge?domain=example.com&token=tok1&provider_id=p1"
    p.click("#o-ddns"); p.fill("#fDdns [name=domain]", "example.com"); p.fill("#fDdns [name=subdomain]", "box"); p.fill("#fDdns [name=ip]", "198.51.100.7")
    p.click("#fDdns button[type=submit]")
    p.wait_for_function("document.getElementById('rDdns').textContent.includes('créé')")
    d = [x for x in appels if x[1] == "/ddns/update"][0]
    assert d[3] == "/ddns/update?provider_id=p1" and json.loads(d[2]) == {"domain": "example.com", "subdomain": "box", "ip": "198.51.100.7"}
    p.click("#o-reglages"); p.fill("#fConf [name=default_ttl]", "120"); p.click("#fConf button[type=submit]")
    p.wait_for_function("document.getElementById('rConf').textContent.includes('enregistrée')")
    c = [x for x in appels if x[1] == "/config" and x[0] == "POST"][0]
    assert json.loads(c[2]) == {"default_ttl": 120, "acme_ttl": 60, "ddns_check_interval": 600, "audit_retention_days": 90}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/dns-provider/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tFourn", "#tDom", "#tEnr", "#tEtat")] == ["—"] * 4 and err == []
    assert p.url == "http://sbx.test/dns-provider/"  # pas de redirection
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/dns-provider/?demo=1", {})
    p.wait_for_selector("#bFourn tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bFourn tr").first.get_by_text("Supprimer").click(); p.locator("#bFourn tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rFourn').textContent.includes('inerte')")
    p.click("#o-enregistrements"); p.click("#lDom button"); p.wait_for_selector("#bEnr td.act")
    p.locator("#bEnr tr").first.get_by_text("Supprimer").click(); p.locator("#bEnr tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rEnr').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/dns-provider/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bFourn tr td.mono", state="attached")
    for onglet in ("fournisseurs", "domaines", "enregistrements", "acme", "ddns", "reglages"):
        p.click("#o-" + onglet)
        if onglet == "enregistrements":
            p.click("#lDom button"); p.wait_for_selector("#bEnr td.mono"); p.click("#addEnr")
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
