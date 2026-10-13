# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /vortex-firewall/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "vortex-firewall" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert re.findall(r'<link rel="stylesheet" href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'vortex-firewall'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC and "document.hidden" in SRC and "ResizeObserver" in SRC
    assert "/login.html?redirect" not in SRC  # plus de redirection brutale sur 401


def test_routes_d_ecriture_a_l_identique():
    for r in ("ecrire('DELETE', '/blocklists/' + encodeURIComponent(nom))", "ecrire('DELETE', '/rules/' + encodeURIComponent(ip))",
              "ecrire('POST', '/blocklists', { name: f.name, url: f.url, format: f.format, enabled: true })",
              "ecrire('POST', '/blocklists', { name, url, format, enabled: true })",
              "ecrire('POST', '/rules', { ip, action, direction, comment })",
              "ecrire('POST', '/enable?enabled=' + cible)", "ecrire('POST', '/blocklists/update')", "ecrire('POST', '/blocklists/apply')"):
        assert r in SRC, r
    assert sorted(re.findall(r"ecrire\('(\w+)', '(/[a-z/]+)", SRC)) == sorted([
        ("DELETE", "/blocklists/"), ("DELETE", "/rules/"), ("POST", "/blocklists"), ("POST", "/blocklists"), ("POST", "/rules"),
        ("POST", "/enable"), ("POST", "/blocklists/update"), ("POST", "/blocklists/apply")])
    # les lectures sont celles de l'ancienne page, rien de plus (pas de /geoip, /info, /status)
    assert set(re.findall(r"lire\('(/[a-z]+)'\)", SRC)) == {"/service", "/stats", "/blocklists", "/rules", "/feeds"}


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def hier(h):
    import datetime
    return (datetime.datetime.now() - datetime.timedelta(hours=h)).isoformat()


SERVICE = {"enabled": True, "nftables_available": True, "blocklists_count": 1, "total_blocked_ips": 1204, "packets_blocked_in": 4200, "packets_blocked_out": 17}
STATS = {"enabled": True, "total_blocked_ips": 1204, "blocklists_count": 1, "custom_rules_count": 1, "packets_blocked_inbound": 4200, "packets_blocked_outbound": 17}
LISTES = {"blocklists": [{"name": "spam<b>x", "url": "https://listes.example.net/s.txt", "enabled": True, "format": "cidr", "ips_count": 1204, "last_updated": hier(2)},
                         {"name": "vide", "url": "https://listes.example.net/v.txt", "enabled": False, "format": "plain", "ips_count": 0, "last_updated": None}]}
REGLES = {"rules": [{"ip": "198.51.100.0/24", "action": "drop", "direction": "both", "comment": "<i>x</i>", "created": hier(5)}]}
FLUX = {"feeds": [{"name": "spam<b>x", "url": "https://x.example.net/a", "format": "cidr", "category": "spam"},
                  {"name": "Flux B", "url": "https://x.example.net/b", "format": "plain", "category": "botnet"}]}
API = {"/service": (200, SERVICE), "/stats": (200, STATS), "/blocklists": (200, LISTES), "/rules": (200, REGLES), "/feeds": (200, FLUX)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "vortex-firewall":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        brut = r.request.url.split("/api/v1/vortex-firewall", 1)[1]
        chemin = brut.split("?")[0]
        appels.append((r.request.method, brut, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(r.request.method + " " + chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/vortex-firewall/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


URL = "http://sbx.test/vortex-firewall/"


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bListes tr td:nth-child(2)", state="attached")
    norm = lambda i: re.sub(r"\s", " ", p.inner_text(i))   # séparateur de milliers fr-FR = espace insécable
    assert [norm(i) for i in ("#tIp", "#tIn", "#tOut", "#tListes", "#tRegles")] == ["1 204", "4 200", "17", "1", "1"]
    assert p.inner_text("#etat") == "ACTIF" and p.inner_text("#nft") == "nftables OK"
    # les noms viennent de l'API : texte, jamais du HTML
    assert p.locator("#bListes b").count() == 0 and "spam<b>x" in p.inner_text("#bListes")
    assert p.locator("#bRegles i").count() == 0 and "<i>x</i>" in p.inner_text("#bRegles")
    # liste jamais téléchargée : nombre d'adresses « — », pas 0
    assert p.locator("#bListes tr").nth(1).locator("td").nth(2).inner_text() == "—"
    # le flux déjà configuré n'a pas de bouton Ajouter (l'API répondrait 400)
    assert "DÉJÀ AJOUTÉ" in p.inner_text("#lFlux") and p.locator("#lFlux button").count() == 1
    assert err == []
    ctx.close()


def test_pare_feu_desactive_compteurs_non_mesures(navigateur):
    off = {**API, "/service": (200, {**SERVICE, "enabled": False}), "/stats": (200, {**STATS, "enabled": False, "packets_blocked_inbound": 0, "packets_blocked_outbound": 0})}
    ctx, p, _, _ = ouvre(navigateur, URL, off)
    p.wait_for_function("document.getElementById('etat').textContent==='DÉSACTIVÉ'")
    assert p.inner_text("#tIn") == "—" and p.inner_text("#tOut") == "—" and p.inner_text("#bascule") == "Activer"
    ctx.close()


def test_retirer_une_liste_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bListes tr td.act button")
    p.locator("#bListes tr").first.get_by_text("Retirer").click()
    assert p.is_visible("#conf") and "spam<b>x" in p.inner_text("#confTxt")
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bListes tr").first.get_by_text("Retirer").click()
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rListes').textContent.includes('retirée')")
    assert ("DELETE", "/blocklists/spam%3Cb%3Ex", None) in appels
    ctx.close()


def test_retirer_une_regle_cidr(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bRegles tr td.act button")
    p.locator("#bRegles tr").first.get_by_text("Retirer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('retirée')")
    assert ("DELETE", "/rules/198.51.100.0%2F24", None) in appels
    ctx.close()


def test_activation_apply_et_mise_a_jour_confirmees_ou_directes(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, "POST /blocklists/apply": (200, {"success": True, "ipv4_blocked": 1205, "ipv6_blocked": 0}),
                                              "POST /blocklists/update": (200, {"results": [{"name": "a", "success": True}, {"name": "b", "success": False}]})})
    p.wait_for_selector("#bListes tr td.act button")
    p.click("#bascule")
    assert "Désactiver le pare-feu" in p.inner_text("#confTxt") and not [a for a in appels if a[0] == "POST"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('toast').textContent.includes('désactivé')")
    assert ("POST", "/enable?enabled=false", None) in appels
    p.click("#appliquer"); assert not [a for a in appels if a[1] == "/blocklists/apply"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rListes').textContent.includes('IPv4 1205')")
    p.click("#majTout")
    p.wait_for_function("document.getElementById('rListes').textContent.includes('échec : b')")
    assert ("POST", "/blocklists/update", None) in appels
    ctx.close()


def test_ajouts_envoient_les_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bListes tr td.act button")
    p.click("#addRegle"); p.fill("#fRegle [name=ip]", "192.0.2.50"); p.select_option("#fRegle [name=direction]", "in"); p.click("#fRegle button[type=submit]")
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('ajoutée')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/rules"][0][2]) == {"ip": "192.0.2.50", "action": "drop", "direction": "in", "comment": None}
    p.click("#addListe"); p.fill("#fListe [name=name]", "ma-liste"); p.fill("#fListe [name=url]", "https://listes.example.net/m.txt"); p.click("#fListe button[type=submit]")
    p.wait_for_function("document.getElementById('rListes').textContent.includes('ajoutée')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/blocklists"][0][2]) == {"name": "ma-liste", "url": "https://listes.example.net/m.txt", "format": "plain", "enabled": True}
    p.get_by_text("Ajouter", exact=True).last.click()
    p.wait_for_function("document.getElementById('rFlux').textContent.includes('Flux B')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/blocklists"][-1][2]) == {"name": "Flux B", "url": "https://x.example.net/b", "format": "plain", "enabled": True}
    ctx.close()


def test_erreur_d_api_affichee_dans_la_page(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, {**API, "POST /rules": (400, {"detail": "Invalid IP format"})})
    p.wait_for_selector("#bListes tr td.act button")
    p.click("#addRegle"); p.fill("#fRegle [name=ip]", "n'importe quoi"); p.click("#fRegle button[type=submit]")
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('Invalid IP format')")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tIp", "#tIn", "#tOut", "#tListes", "#tRegles")] == ["—"] * 5 and err == []
    assert not p.is_visible("#bascule") and p.url == URL
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#bListes tr td.act button")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bListes tr").first.get_by_text("Retirer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rListes').textContent.includes('inerte')")
    p.click("#appliquer"); p.click("#confOui")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bListes tr td.act button")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
