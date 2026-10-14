# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /picobrew/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "picobrew" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'picobrew'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_a_l_identique():
    assert "const API = '/api/v1/picobrew'" in SRC
    for r in ("'/status'", "'/logs'", "'/' + a.verbe, 'POST'", "data-verbe=\"start\"", "data-verbe=\"stop\"", "data-verbe=\"restart\""):
        assert r in SRC
    assert SRC.count("'POST'") == 1  # une seule écriture, pour start/stop/restart


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"installed": True, "running": True, "ip": "192.0.2.150", "pinned_sha": "0123456789abcdef0123456789abcdef01234567", "session_active": False, "mem_mb": 312}
API = {"/status": (200, STATUS), "/logs": (200, {"lines": ["ligne un", "ligne <b>deux</b>"]}),
       "/start": (200, {"ok": True}), "/stop": (200, {"ok": True}), "/restart": (200, {"ok": True})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://admin.sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "picobrew":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://admin.sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/picobrew", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://admin.sbx.test/api/v1/picobrew/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_journal_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://admin.sbx.test/picobrew/", API)
    p.wait_for_function("document.getElementById('tSha').textContent !== '—'")
    assert p.inner_text("#etat") == "EN MARCHE" and p.inner_text("#tEtat") == "en marche"
    assert p.inner_text("#tSha") == "0123456789" and p.inner_text("#tMem") == "312 Mo" and p.inner_text("#tSession") == "non"
    assert p.inner_text("#kLan") == "http://192.0.2.150/"
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne')")
    assert "<b>deux</b>" in p.inner_text("#journal")  # texte brut, jamais interprété
    assert p.get_attribute("#aOuvrir", "href") == "https://picobrew.sbx.test/"
    assert p.is_disabled("#bStart") and not p.is_disabled("#bStop")
    assert err == []
    ctx.close()


def test_arret_demande_confirmation_dans_la_page_et_envoie_post(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://admin.sbx.test/picobrew/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.wait_for_function("document.getElementById('tSha').textContent !== '—'")
    p.click("#bStop")
    assert p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]
    p.click("#ouiConfirm")
    p.wait_for_function("document.getElementById('retour').textContent.includes('demandé')")
    post = [a for a in appels if a[0] == "POST"]
    assert [(a[1], a[2]) for a in post] == [("/stop", None)] and err == []
    ctx.close()


def test_annuler_n_envoie_rien_et_session_active_avertit(navigateur):
    routes = {**API, "/status": (200, {**STATUS, "session_active": True})}
    ctx, p, _, appels = ouvre(navigateur, "http://admin.sbx.test/picobrew/", routes)
    p.wait_for_function("document.getElementById('tSha').textContent !== '—'")
    assert p.inner_text("#tSession") == "oui"
    p.click("#bRestart")
    assert "interrompue" in p.inner_text("#confirmTexte")
    p.click("#nonConfirm")
    assert not p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_jeton_envoye_en_bearer(navigateur):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    vus = []
    p.route("http://admin.sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC) if r.request.url.endswith("/picobrew/") else
            (vus.append(r.request.headers.get("authorization")), r.fulfill(status=200, content_type="application/json", body=json.dumps(STATUS)))
            if "/api/" in r.request.url else r.fulfill(status=200, content_type="text/css", body=""))
    p.goto("http://admin.sbx.test/picobrew/")
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.reload()
    p.wait_for_function("document.getElementById('tSha').textContent !== '—'")
    assert "Bearer jeton-test" in vus
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://admin.sbx.test/picobrew/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEtat", "#tSha", "#tSession", "#tMem")] == ["—"] * 4 and err == []
    assert p.is_disabled("#bStop") and p.is_disabled("#bStart")
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://admin.sbx.test/picobrew/?demo=1", {})
    p.wait_for_function("document.getElementById('tSha').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bStop")
    assert "inerte" in p.inner_text("#retour") and not p.is_visible("#confirm")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://admin.sbx.test/picobrew/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tSha').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
