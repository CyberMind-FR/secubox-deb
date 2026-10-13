# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /ipblock/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "ipblock" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'ipblock'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC and "document.hidden" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'POST', '/list/add'", "'POST', '/list/' + encodeURIComponent(id) + '/update'", "'DELETE', '/list/' + encodeURIComponent(id)",
              "'POST', '/lists/update-all'", "'POST', '/block', { ip, reason", "'DELETE', '/block/' + encodeURIComponent(ip)",
              "'POST', '/whitelist', { ip, reason", "'DELETE', '/whitelist/' + encodeURIComponent(ip)", "'POST', '/import', { name, format",
              "'POST', '/apply'", "'POST', '/config', { auto_update_enabled", "update_interval", "log_blocked", "block_action",
              "enabled: true, auto_update: true", "/export?include_manual=true&include_lists=true"):
        assert r in SRC, r
    # aucune route d'écriture inventée
    assert set(re.findall(r"ecrire\('(\w+)', '(/[a-z-]+)", SRC)) == {
        ("POST", "/list"), ("DELETE", "/list"), ("POST", "/lists"), ("DELETE", "/block"), ("POST", "/block"),
        ("DELETE", "/whitelist"), ("POST", "/whitelist"), ("POST", "/import"), ("POST", "/apply"), ("POST", "/config")}


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


STATS = {"enabled": True, "total_blocked_ips": 1204, "list_ips": 1200, "manual_blocks": 4, "whitelisted": 2, "active_sources": 1,
         "packets_dropped": 0, "last_update": hier(2), "nftables_available": True}
LISTS = {"sources": [{"id": "ab12", "name": "spam<b>x", "url": "https://listes.example.net/s.txt", "enabled": True, "format": "cidr", "category": "spam",
                      "auto_update": True, "ip_count": 1200, "last_updated": hier(2)}]}
AVAIL = {"sources": [{"id": "d1", "name": "spam<b>x", "url": "https://listes.example.net/s.txt", "format": "cidr", "category": "spam"},
                     {"id": "d2", "name": "botnet-demo", "url": "https://listes.example.net/b.txt", "format": "plain", "category": "botnet"}]}
BLOCKED = {"blocked": [{"ip": "203.0.113.9", "reason": "Balayage", "added": hier(5), "expires": None, "source": "manual"},
                       {"ip": "198.51.100.0/24", "reason": None, "added": hier(30), "expires": hier(1), "source": "manual"}], "count": 2}
WL = {"whitelist": [{"ip": "192.0.2.10", "reason": "Supervision", "added": hier(50)}], "count": 1}
HIST = {"history": [{"id": "h1", "timestamp": hier(5), "action": "blocked", "ip": "203.0.113.9", "source": "manual", "reason": "Balayage"},
                    {"id": "h2", "timestamp": hier(6), "action": "list_added", "ip": "-", "source": "spam", "reason": "x"}], "total": 2}
CFG = {"auto_update_enabled": False, "update_interval": 7200, "log_blocked": True, "block_action": "reject"}
API = {"/stats": (200, STATS), "/lists": (200, LISTS), "/lists/available": (200, AVAIL), "/blocked": (200, BLOCKED),
       "/whitelist": (200, WL), "/history": (200, HIST), "/config": (200, CFG)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "ipblock":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/ipblock", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/ipblock/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ipblock/", API)
    p.wait_for_selector("#bSrc tr td.cassable", state="attached")
    # 0 est une mesure : « 0 », pas « — »
    assert [p.inner_text(i) for i in ("#tSources", "#tManuel", "#tBlanche", "#tPaquets")] == ["1", "4", "2", "0"]
    assert p.inner_text("#tTotal").replace(" ", " ").replace("\xa0", " ") == "1 204"
    assert p.inner_text("#etat") == "BLOCAGE ACTIF"
    # nom avec balise : affiché en texte, jamais interprété
    assert "spam<b>x" in p.inner_text("#bSrc") and p.locator("#bSrc b").count() == 0
    assert "203.0.113.9" in p.inner_text("#bBlq") and "ÉCHUE" in p.inner_text("#bBlq") and "Jamais" in p.inner_text("#bBlq")
    assert "192.0.2.10" in p.inner_text("#bBl") and "BLOQUÉE" in p.inner_text("#bHis")
    assert "DÉJÀ AJOUTÉE" in p.inner_text("#lDispo") and "botnet-demo" in p.inner_text("#lDispo")
    # réglages : 7200 s -> 2 h, décoché, rejeter
    assert p.input_value("#cfgInterval") == "2" and not p.is_checked("#cfgAuto") and p.input_value("#cfgAction") == "reject"
    assert err == []
    ctx.close()


def test_onglets(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/ipblock/", API)
    p.wait_for_selector("#bSrc tr", state="attached")
    p.click("#o-bloquees")
    assert p.get_attribute("#o-bloquees", "aria-selected") == "true" and p.is_visible("#t-bloquees") and not p.is_visible("#t-apercu")
    ctx.close()


def test_debloquer_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ipblock/", {**API, "/block/203.0.113.9": (200, {"success": True})})
    p.click("#o-bloquees"); p.wait_for_selector("#bBlq tr td.act")
    p.locator("#bBlq tr").first.get_by_text("Débloquer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    assert "Débloquer 203.0.113.9" in p.inner_text("#cBlq")
    p.get_by_role("button", name="Annuler").click()
    assert p.inner_text("#cBlq") == "" and not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bBlq tr").first.get_by_text("Débloquer").click()
    p.get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('rBlq').textContent.includes('débloquée')")
    assert ("DELETE", "/block/203.0.113.9", None) in appels
    ctx.close()


def test_retirer_une_liste_demande_confirmation_et_annonce_le_volume(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ipblock/", {**API, "/list/ab12": (200, {"success": True})})
    p.click("#o-listes"); p.wait_for_selector("#bSrc tr td.act")
    p.locator("#bSrc tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    assert "1" in p.inner_text("#cSrc") and "débloquées en une fois" in p.inner_text("#cSrc")
    p.get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('rSrc').textContent.includes('retirée')")
    assert ("DELETE", "/list/ab12", None) in appels
    ctx.close()


def test_bloquer_envoie_le_meme_corps_et_valide_la_duree(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ipblock/", API)
    p.click("#o-bloquees"); p.click("#addBlq")
    p.fill("#fBlq [name=ip]", "203.0.113.50"); p.fill("#fBlq [name=reason]", "Test"); p.fill("#fBlq [name=duration]", "2")
    p.click("#fBlq button[type=submit]")
    p.wait_for_function("document.getElementById('rBlq').textContent.includes('bloquée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/block"][0]
    assert json.loads(post[2]) == {"ip": "203.0.113.50", "reason": "Test", "duration": 7200}
    p.click("#addBlq"); p.fill("#fBlq [name=ip]", "203.0.113.51"); p.fill("#fBlq [name=duration]", "1.5")
    p.click("#fBlq button[type=submit]")
    p.wait_for_function("document.getElementById('rBlq').textContent.includes('nombre entier')")
    assert len([a for a in appels if a[0] == "POST" and a[1] == "/block"]) == 1
    ctx.close()


def test_liste_blanche_source_import_config_et_application(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ipblock/", {**API, "/apply": (200, {"success": True, "blocked_v4": 5, "blocked_v6": 1})})
    p.wait_for_selector("#bSrc tr", state="attached")
    p.click("#o-blanche"); p.click("#addBl"); p.fill("#fBl [name=ip]", "192.0.2.77"); p.click("#fBl button[type=submit]")
    p.wait_for_function("document.getElementById('rBl').textContent.includes('ajoutée')")
    assert json.loads([a for a in appels if a[1] == "/whitelist" and a[0] == "POST"][0][2]) == {"ip": "192.0.2.77", "reason": None}
    p.click("#o-listes")
    p.get_by_role("button", name="Ajouter").last.click()      # source proposée « botnet-demo »
    p.wait_for_function("document.getElementById('rSrc').textContent.includes('ajoutée')")
    assert json.loads([a for a in appels if a[1] == "/list/add" and a[0] == "POST"][0][2]) == {"enabled": True, "auto_update": True, "name": "botnet-demo", "url": "https://listes.example.net/b.txt", "format": "plain", "category": "botnet"}
    p.click("#o-historique"); p.click("#addImp"); p.fill("#fImp [name=name]", "ma-liste"); p.fill("#fImp [name=content]", "192.0.2.1\n192.0.2.2")
    p.click("#fImp button[type=submit]")
    assert json.loads([a for a in appels if a[1] == "/import" and a[0] == "POST"][0][2]) == {"name": "ma-liste", "format": "plain", "content": "192.0.2.1\n192.0.2.2"}
    p.click("#o-reglages"); p.fill("#cfgInterval", "12"); p.check("#cfgAuto"); p.click("#fCfg button[type=submit]")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('enregistrée')")
    assert json.loads([a for a in appels if a[1] == "/config" and a[0] == "POST"][0][2]) == {"auto_update_enabled": True, "update_interval": 43200, "log_blocked": True, "block_action": "reject"}
    p.fill("#cfgInterval", "500"); p.click("#fCfg button[type=submit]")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('entre 1 et 168')")
    p.click("#appliquer")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('5 adresses IPv4')")
    assert ("POST", "/apply", None) in appels
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ipblock/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tSources", "#tListes", "#tManuel", "#tBlanche", "#tPaquets")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/ipblock/?demo=1", {})
    p.wait_for_selector("#bSrc tr td.cassable", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-listes"); p.locator("#bSrc tr").first.get_by_text("Mettre à jour").click()
    p.wait_for_function("document.getElementById('rSrc').textContent.includes('inerte')")
    p.click("#appliquer")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ipblock/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bSrc tr td.cassable", state="attached")
    for t in ("o-apercu", "o-listes", "o-bloquees", "o-blanche", "o-historique", "o-reglages"):
        p.click("#" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
