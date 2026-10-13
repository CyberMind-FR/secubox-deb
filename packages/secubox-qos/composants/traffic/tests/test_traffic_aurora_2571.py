# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /traffic/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "traffic" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for ancien in ("googleapis", "/shared/crt-engine.js", "hybrid-dark", "crt-light", "login.html?redirect"):
        assert ancien not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'traffic'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_identiques_a_l_ancienne_page():
    # POST /class/add, /class/delete, /rule/add, /rule/delete, /preset/apply, /apply, /clear
    for r in ("'/class/add'", "'/class/delete'", "'/rule/add'", "'/rule/delete'", "'/preset/apply'", "'/apply'", "'/clear'"):
        assert r in SRC
    assert len(re.findall(r"ecrire\('/", SRC)) == 7
    assert "method: 'POST'" in SRC and "'DELETE'" not in SRC
    assert "class_id: f.class_id.value" in SRC and "{ preset: id }" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"active": True, "qdisc_count": 2, "class_count": 2, "rule_count": 1, "interfaces": ["eth0", "wan"]}
CLASSES = {"classes": [{"id": "gaming", "name": "Jeux", "priority": 1, "rate": "10mbit", "ceil": "50mbit", "interface": "wan", "enabled": True},
                       {"id": "default", "name": "Défaut", "priority": 5, "rate": "3mbit", "ceil": "20mbit", "interface": "wan", "enabled": True}], "total": 2}
RULES = {"rules": [{"id": "r1", "class": "gaming", "match_type": "dport", "match_value": "3074", "enabled": True}], "total": 1}
STATS = {"stats": [{"class": "1:10", "packets": 1500, "bytes": 3145728, "drops": 3}, {"class": "1:20", "packets": 10, "bytes": 1048576, "drops": 0}], "total": 2}
API = {"/status": (200, STATUS), "/classes": (200, CLASSES), "/rules": (200, RULES), "/stats": (200, STATS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "traffic":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/traffic", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/traffic/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/traffic/", API)
    p.wait_for_selector("#bStats tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tClasses", "#tRegles", "#tQdisc", "#tIfaces", "#tOctets")] == ["2", "1", "2", "2", "4.00 Mio"]
    assert p.inner_text("#etat") == "ACTIF"
    # la règle référence l'identifiant de classe : la page affiche le nom
    assert "Jeux" in p.inner_text("#bRegles") and "3074" in p.inner_text("#bRegles") and "gaming" not in p.inner_text("#bRegles")
    assert "50mbit" in p.inner_text("#bClasses") and "1 500" in p.inner_text("#bStats").replace(" ", " ").replace("\xa0", " ")
    assert err == []
    ctx.close()


def test_supprimer_une_classe_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/traffic/", API)
    p.wait_for_selector("#bClasses tr td.act")
    p.locator("#bClasses tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "POST"]          # pas encore : il faut confirmer
    p.locator("#bClasses tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCl').textContent.includes('supprimée')")
    assert ("POST", "/class/delete", json.dumps({"id": "gaming"}, separators=(",", ":"))) in appels
    ctx.close()


def test_ajout_classe_et_regle_envoient_les_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/traffic/", API)
    p.wait_for_selector("#bClasses tr td.act")
    p.click("#addClasse"); p.fill("#fClasse [name=name]", "Voix"); p.select_option("#fClasse [name=priority]", "2")
    p.click("#fClasse button[type=submit]")
    p.wait_for_function("document.getElementById('rCl').textContent.includes('créée')")
    post = [a for a in appels if a[1] == "/class/add"][0]
    assert json.loads(post[2]) == {"name": "Voix", "priority": 2, "rate": "1mbit", "ceil": "10mbit", "interface": "wan"}
    p.click("#addRegle"); p.select_option("#fRegle [name=class_id]", "default"); p.fill("#fRegle [name=match_value]", "443")
    p.click("#fRegle button[type=submit]")
    p.wait_for_function("document.getElementById('rRe').textContent.includes('créée')")
    assert json.loads([a for a in appels if a[1] == "/rule/add"][0][2]) == {"class_id": "default", "match_type": "dport", "match_value": "443"}
    ctx.close()


def test_preset_et_effacement_se_confirment_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/traffic/", API)
    p.wait_for_selector("#presets .preset")
    p.locator("#presets .preset").nth(2).click()
    assert p.is_visible("#cPre") and not [a for a in appels if a[0] == "POST"]
    p.click("#cPreOui")
    p.wait_for_function("document.getElementById('rPre').textContent.includes('appliqué')")
    assert json.loads([a for a in appels if a[1] == "/preset/apply"][0][2]) == {"preset": "work_from_home"}
    p.click("#effacer")
    assert p.is_visible("#cAct") and not [a for a in appels if a[1] == "/clear"]
    p.click("#cActOui")
    p.wait_for_function("document.getElementById('rAct').textContent.includes('effacée')")
    assert any(a[1] == "/clear" for a in appels)
    p.click("#appliquer")
    p.wait_for_function("document.getElementById('rAct').textContent.includes('appliquée')")
    assert any(a[1] == "/apply" for a in appels)
    ctx.close()


def test_echec_d_ecriture_affiche_le_detail_de_l_api(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/traffic/", {**API, "/class/delete": (404, {"detail": "Class not found"})})
    p.wait_for_selector("#bClasses tr td.act")
    p.locator("#bClasses tr").first.get_by_text("Supprimer").click()
    p.locator("#bClasses tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCl').textContent.includes('Class not found')")
    ctx.close()


def test_sans_session_bandeau_et_tirets_sans_redirection(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/traffic/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tClasses", "#tRegles", "#tQdisc", "#tIfaces", "#tOctets")] == ["—"] * 5
    assert p.url.startswith("http://sbx.test/traffic/") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/traffic/?demo=1", {})
    p.wait_for_selector("#bClasses tr td.act")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bClasses tr").first.get_by_text("Supprimer").click()
    p.locator("#bClasses tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCl').textContent.includes('inerte')")
    p.click("#appliquer")
    p.wait_for_function("document.getElementById('rAct').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_menu_masque_en_embed(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/traffic/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bStats tr td.mono", state="attached")
    p.click("#addClasse"); p.click("#addRegle")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
