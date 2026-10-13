# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /mqtt/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "mqtt" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "/shared/api-utils.js" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'mqtt'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_lues_sont_celles_du_module_mqtt_et_aucune_ecriture():
    # l'ancienne page appelait /api/v1/lyrion (copier-coller) : jamais plus
    assert "lyrion" not in SRC.lower()
    assert "const API = '/api/v1/mqtt'" in SRC
    for r in ("'/components'", "'/status'", "'/access'"):
        assert r in SRC
    # l'ancienne page n'écrivait pas : la nouvelle non plus
    for w in ("POST", "PUT", "DELETE", "PATCH", "method:"):
        assert w not in SRC


def test_aucun_identifiant_de_courtier_affiche():
    assert "a.user" not in SRC and ".user" not in SRC and "password" not in SRC.lower()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


COMP = {"module": "mqtt", "version": "2.5.0", "components": [
    {"name": "lxc", "state": "running", "detail": "mqtt @ 192.0.2.110 on br-lxc"},
    {"name": "broker", "state": "running", "detail": "mosquitto, port 1883"},
    {"name": "health", "state": "degraded", "detail": "pub round-trip via secubox-api"}]}
STAT = {"module": "mqtt", "version": "2.5.0", "overall": "yellow", "states": {"lxc": "running", "broker": "running", "health": "degraded"}}
ACCESS = {"module": "mqtt", "access": [
    {"user": "compte-secret-zz", "mode": "readwrite", "topic": "zigbee2mqtt/#", "scope": "lan"},
    {"user": "autre-compte-yy", "mode": "read", "topic": "homeassistant/#", "scope": "lan"}]}
API = {"/components": (200, COMP), "/status": (200, STAT), "/access": (200, ACCESS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "mqtt":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/mqtt", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/mqtt/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mqtt/", API)
    p.wait_for_selector("#bAcl tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tGlobal", "#tLxc", "#tBroker", "#tHealth", "#tRegles")] == ["Dégradé", "EN MARCHE", "EN MARCHE", "DÉGRADÉ", "2"]
    assert p.inner_text("#etat") == "DÉGRADÉ" and p.inner_text("#kVer") == "2.5.0"
    assert "192.0.2.110" in p.inner_text("#bComp") and "zigbee2mqtt/#" in p.inner_text("#bAcl")
    assert "Lecture et écriture" in p.inner_text("#bAcl")
    # aucun nom de compte de courtier affiché
    assert "compte-secret-zz" not in p.inner_text("body") and "autre-compte-yy" not in p.inner_text("body")
    assert all(a[0] == "GET" for a in appels) and err == []
    ctx.close()


def test_cache_acl_absent_n_est_pas_une_erreur_de_session(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mqtt/", {**API, "/access": (503, {"detail": "ACL cache absent"})})
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert p.is_hidden("#session") and p.inner_text("#tRegles") == "—" and "indisponible" in p.inner_text("#bAcl")
    assert p.inner_text("#tGlobal") == "Dégradé" and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mqtt/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tGlobal", "#tLxc", "#tBroker", "#tHealth", "#tRegles")] == ["—"] * 5 and err == []
    ctx.close()


def test_jeton_envoye_depuis_sbx_token(navigateur):
    ctx = navigateur.new_context()
    ctx.add_init_script("localStorage.setItem('sbx_token','jeton-test')")
    p = ctx.new_page(); en_tetes = []
    p.route("http://sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC) if r.request.url.rstrip("/").endswith("mqtt")
            else r.fulfill(status=200, content_type="application/javascript", body="") if "/shared/" in r.request.url
            else (en_tetes.append(r.request.headers.get("authorization")), r.fulfill(status=200, content_type="application/json", body=json.dumps(COMP)))[1])
    p.goto("http://sbx.test/mqtt/"); p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert en_tetes and set(en_tetes) == {"Bearer jeton-test"}
    ctx.close()


def test_demonstration_annoncee_sans_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mqtt/?demo=1", {})
    p.wait_for_selector("#bAcl tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tGlobal") == "Sain"
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mqtt/?embed=1", API, taille={"width": 420, "height": 800})
    p.evaluate("window.__h=[];addEventListener('message',e=>window.__h.push(e.data))")
    p.wait_for_selector("#bAcl tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
