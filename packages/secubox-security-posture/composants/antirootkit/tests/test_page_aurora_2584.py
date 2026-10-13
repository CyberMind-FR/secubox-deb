# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /antirootkit/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "antirootkit" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-skin" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'antirootkit'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_lectures_et_ecriture_identiques():
    for r in ("'/status'", "'/execlog?limit=100'", "'/alerts'", "/quarantine-prep", "method: 'POST'"):
        assert r in SRC
    assert "path: path, c2_ip: c2 || null, unit: unite || null" in SRC  # corps inchangé
    assert len(re.findall(r"method: '(?:POST|PUT|DELETE|PATCH)'", SRC)) == 1  # aucune écriture nouvelle
    assert "sbx_token" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = time.time()
STATUS = {"execlog_rows": 1234}
EXEC = [
    {"ts": NOW - 20, "pid": 11, "ppid": 1, "uid": 0, "exe": "/usr/bin/ls", "argv": "[]", "success": 1, "verdict": "allow", "pkg": "coreutils"},
    {"ts": NOW - 60, "pid": 12, "ppid": 1, "uid": 33, "exe": "/tmp/mal", "argv": "[]", "success": 1, "verdict": "jail", "pkg": None},
    {"ts": NOW - 90, "pid": 13, "ppid": 1, "uid": 1000, "exe": "/home/x/inconnu", "argv": "[]", "success": 0, "verdict": "jail", "pkg": None},
]
ALERTES = [{"exe": "/tmp/mal", "pid": 12, "score": 90, "reasons": ["non rattaché", "tmp"], "dest": "203.0.113.50", "ioc": True},
           {"exe": "/home/x/inconnu", "pid": 13, "score": 55, "reasons": [], "dest": None, "ioc": False}]
PLAN = {"chmod": "chmod 000 /tmp/mal", "copy": "cp -a /tmp/mal /root/quarantine/", "sha256": None,
        "nft_block": "nft add rule inet filter output ip daddr 203.0.113.50 drop", "disable_unit": None}
API = {"/status": (200, STATUS), "/execlog": (200, EXEC), "/alerts": (200, ALERTES), "/quarantine-prep": (200, PLAN)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "antirootkit":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/antirootkit", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/antirootkit/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/antirootkit/", API)
    p.wait_for_selector("#bExec tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tEvt", "#tAlertes", "#tCage", "#tOrph")] == ["1234", "2", "2", "2"]
    assert "1 avec IOC" in p.inner_text("#sAlertes") and "il y a" in p.inner_text("#tDernier")
    assert p.inner_text("#etat") == "API EN LIGNE"
    assert "/tmp/mal" in p.inner_text("#bAlertes") and "IOC" in p.inner_text("#bAlertes") and "203.0.113.50" in p.inner_text("#bAlertes")
    assert "coreutils" in p.inner_text("#bExec") and "MIS EN CAGE" in p.inner_text("#bExec") and "ÉCHEC" in p.inner_text("#bExec")
    assert "1970" not in p.inner_text("#bExec")
    p.check("#fOrph")
    assert "coreutils" not in p.inner_text("#bExec") and "2 / 3" in p.inner_text("#nExec")
    assert err == []
    ctx.close()


def test_plan_envoie_le_meme_corps_et_jeton(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/antirootkit/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.wait_for_selector("#bAlertes tr td.act")
    p.fill("#qpPath", "/tmp/mal"); p.fill("#qpC2", "203.0.113.50")
    p.click("#qpBtn")
    p.wait_for_selector("#plan:not([hidden])")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/quarantine-prep" and json.loads(post[2]) == {"path": "/tmp/mal", "c2_ip": "203.0.113.50", "unit": None}
    assert post[3] == "Bearer jeton-test"
    assert "chmod 000 /tmp/mal" in p.inner_text("#plan") and "—" in p.inner_text("#plan")
    assert err == []
    ctx.close()


def test_bouton_plan_de_l_alerte_prerempli_le_formulaire(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/antirootkit/", API)
    p.wait_for_selector("#bAlertes tr td.act")
    p.locator("#bAlertes tr").first.get_by_text("Plan").click()
    p.wait_for_selector("#plan:not([hidden])")
    assert p.input_value("#qpPath") == "/tmp/mal" and p.input_value("#qpC2") == "203.0.113.50"
    assert json.loads([a for a in appels if a[0] == "POST"][0][2]) == {"path": "/tmp/mal", "c2_ip": "203.0.113.50", "unit": None}
    assert err == []
    ctx.close()


def test_chemin_obligatoire_sans_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/antirootkit/", API)
    p.wait_for_selector("#bExec tr td.mono", state="attached")
    p.evaluate("document.getElementById('fQp').dispatchEvent(new Event('submit',{cancelable:true}))")
    assert "obligatoire" in p.inner_text("#rPlan") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_refus_du_plan_affiche_l_erreur(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/antirootkit/", {**API, "/quarantine-prep": (403, {"detail": "interdit"})})
    p.wait_for_selector("#bExec tr td.mono", state="attached")
    p.fill("#qpPath", "/tmp/x"); p.click("#qpBtn")
    p.wait_for_function("document.getElementById('rPlan').textContent.includes('403')")
    assert p.is_hidden("#plan") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/antirootkit/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEvt", "#tAlertes", "#tCage", "#tOrph", "#tDernier")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_action_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/antirootkit/?demo=1", {})
    p.wait_for_selector("#bExec tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bAlertes tr").first.get_by_text("Plan").click()
    p.wait_for_function("document.getElementById('rPlan').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/antirootkit/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bExec tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
