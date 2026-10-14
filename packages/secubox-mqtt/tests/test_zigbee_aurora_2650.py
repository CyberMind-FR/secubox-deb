# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2650 — /zigbee/ au profil Aurora (composant de secubox-mqtt) : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "zigbee" / "www" / "zigbee" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for interdit in ("hybrid-dark", "crt-light", "/shared/api-utils.js", "fonts.googleapis", "confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'zigbee'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_et_ecritures_a_l_identique():
    assert "const API = '/api/v1/zigbee'" in SRC
    for r in ("'/components'", "'/status'", "'/access'", "'/backups'", "'POST', '/backup'", "'POST', '/restore', { id: id }"):
        assert r in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer '" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


COMP = {"components": [
    {"name": "lxc", "state": "running", "detail": "zigbee @ 192.0.2.111 on br-lxc"},
    {"name": "device", "state": "absent", "detail": "/dev/secubox-zgb"},
    {"name": "daemon", "state": "running", "detail": "zigbee2mqtt frontend :8080"},
    {"name": "bridge", "state": "offline", "detail": "zigbee2mqtt/bridge/state"}]}
STAT = {"overall": "yellow", "states": {"lxc": "running", "device": "absent", "daemon": "running", "bridge": "offline"}}
ACCES = {"access": [{"url": "https://zigbee.exemple.test/", "scope": "public", "auth": "LAN-gated"},
                    {"url": "http://192.0.2.111:8080/", "scope": "lan", "auth": "none"},
                    {"url": "mqtt://192.0.2.110:1883 (zigbee2mqtt/#)", "scope": "lan-mqtt", "auth": "z2m user"}]}
SAUV = {"backups": [{"id": "20261012T070000Z", "kind": "hourly", "size_db": 184320, "devices": 14, "timestamp": "20261012T070000Z"},
                    {"id": "pre-restore-20261011T180200Z", "kind": "pre-restore", "size_db": 1024, "devices": 0, "timestamp": "20261011T180200Z"}]}
API = {"/components": (200, COMP), "/status": (200, STAT), "/access": (200, ACCES), "/backups": (200, SAUV)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "zigbee":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/zigbee", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"ok": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/zigbee/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_tableaux_et_lien_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/zigbee/", API)
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    assert p.inner_text("#etat") == "DÉGRADÉ"
    assert [p.inner_text(i) for i in ("#tGlobal", "#tLxc", "#tRadio", "#tDemon", "#tPont", "#tSauv")] == \
        ["Jaune", "En marche", "Absente", "En marche", "Hors ligne", "2"]
    assert "192.0.2.111" in p.inner_text("#bComp") and "mqtt://192.0.2.110:1883" in p.inner_text("#lAcces")
    assert p.get_attribute("#ouvrir", "href") == "https://zigbee.exemple.test/" and p.is_visible("#ouvrir")
    # les URL non http(s) ne deviennent jamais des liens
    assert p.locator("#lAcces a").count() == 2
    t = p.inner_text("#bSauv")
    assert "2026-10-12 07:00:00 UTC" in t and "AVANT RESTAURATION" in t and "180,0 Ko" in t
    assert all(p.get_attribute(i, "title") for i in ("#cGlobal", "#cLxc", "#cRadio", "#cDemon", "#cPont", "#cSauv"))
    assert err == []
    ctx.close()


def test_sauvegarder_maintenant(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/zigbee/", API)
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    p.click("#sauvMaintenant")
    p.wait_for_function("document.getElementById('rSauv').textContent.includes('Sauvegarde effectuée')")
    assert [a for a in appels if a[0] == "POST" and a[1] == "/backup"]
    assert err == []
    ctx.close()


def test_sauvegarde_refusee_affiche_le_motif(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/zigbee/", {**API, "/backup": (200, {"ok": False, "error": "missing /usr/sbin/zigbee-backup"})})
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    p.click("#sauvMaintenant")
    p.wait_for_function("document.getElementById('rSauv').textContent.includes('missing')")
    assert "impossible" in p.inner_text("#rSauv")
    ctx.close()


def test_restauration_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/zigbee/", API)
    p.wait_for_selector("#bSauv tr td.act")
    p.locator("#bSauv tr").first.get_by_text("Restaurer").click()
    assert not [a for a in appels if a[1] == "/restore"]          # pas encore : il faut confirmer
    p.locator("#bSauv tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSauv').textContent.includes('Restauration effectuée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/restore"][0]
    assert json.loads(post[2]) == {"id": "20261012T070000Z"}
    assert err == []
    ctx.close()


def test_annuler_ne_restaure_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/zigbee/", API)
    p.wait_for_selector("#bSauv tr td.act")
    p.locator("#bSauv tr").first.get_by_text("Restaurer").click()
    p.locator("#bSauv tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[1] == "/restore"]
    ctx.close()


def test_jeton_envoye_en_bearer(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/zigbee/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#sauvMaintenant")
    p.wait_for_function("document.getElementById('rSauv').textContent.includes('effectuée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/backup"][0]
    assert post[3] == "Bearer jeton-test"
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/zigbee/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tGlobal", "#tLxc", "#tRadio", "#tDemon", "#tPont", "#tSauv")] == ["—"] * 6
    assert not p.is_visible("#ouvrir") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/zigbee/?demo=1", {})
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#sauvMaintenant")
    p.wait_for_function("document.getElementById('rSauv').textContent.includes('inerte')")
    p.locator("#bSauv tr").first.get_by_text("Restaurer").click()
    p.locator("#bSauv tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSauv').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/zigbee/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
