# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /reporter/ au profil Aurora : contrôles statiques + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "reporter" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'reporter'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    assert "ecrire('DELETE', '/reports/' + encodeURIComponent(id))" in SRC
    assert "ecrire('POST', '/reports/generate', corps)" in SRC
    assert "ecrire('POST', '/schedule', corps)" in SRC
    assert "ecrire('POST', '/schedule', { report_type: type, format: courant.format, cron: courant.cron, enabled: actif })" in SRC
    for cle in ("report_type", "format", "title", "start_date", "end_date", "sections", "cron", "enabled"):
        assert cle + ":" in SRC
    # aucune écriture inventée : un seul POST /reports/generate, deux POST /schedule, un DELETE
    assert len(re.findall(r"ecrire\('", SRC)) == 4


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATS = {"reports_summary": {"total": 3, "completed": 2, "pending": 1, "failed": 0}}
REPORTS = {"reports": [
    {"id": "r1", "report_type": "daily", "format": "pdf", "status": "completed", "created_at": "2026-10-13T06:00:00", "title": "<b>Quotidien</b>", "file_size": 2048},
    {"id": "r2", "report_type": "security", "format": "html", "status": "pending", "created_at": "2026-10-13T07:00:00", "title": "Sécurité", "file_size": None}],
    "total": 2, "limit": 50, "offset": 0}
SCHEDULE = {"enabled": False, "schedules": [{"id": "daily", "cron": "0 6 * * *", "report_type": "daily", "format": "pdf", "enabled": False, "description": "Quotidien"}]}
API = {"/stats": (200, STATS), "/reports": (200, REPORTS), "/schedule": (200, SCHEDULE)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "reporter":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/reporter", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/reporter/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api_et_titre_echappe(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/reporter/", API)
    p.wait_for_selector("#bRap tr td.act", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tOk", "#tAtt", "#tKo")] == ["3", "2", "1", "0"]
    txt = p.inner_text("#bRap")
    assert "<b>Quotidien</b>" in txt and "2,0 Ko" in txt and "EN ATTENTE" in txt and "TERMINÉ" in txt
    assert p.locator("#bRap b").count() == 0          # le titre n'est jamais interprété comme du HTML
    assert err == []
    ctx.close()


def test_suppression_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/reporter/", {**API, "/reports/r1": (200, {"success": True})})
    p.wait_for_selector("#bRap tr td.act", state="attached")
    p.locator("#bRap tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bRap tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRap').textContent.includes('supprimé')")
    assert ("DELETE", "/reports/r1", None) in appels
    ctx.close()


def test_generation_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/reporter/", {**API, "/reports/generate": (200, {"success": True, "report_id": "zz9"})})
    p.click("#o-generer")
    p.select_option("#gType", "security"); p.select_option("#gFormat", "html"); p.fill("#gTitre", "Mon rapport"); p.fill("#gDebut", "2026-10-01")
    p.uncheck("#gSections input[value=waf_alerts]")
    p.click("#fGen button[type=submit]")
    p.wait_for_function("document.getElementById('rGen').textContent.includes('zz9')")
    corps = json.loads([a for a in appels if a[0] == "POST" and a[1] == "/reports/generate"][0][2])
    assert corps == {"report_type": "security", "format": "html", "title": "Mon rapport", "start_date": "2026-10-01", "end_date": None,
                     "sections": ["security_events", "blocked_ips", "auth_failures"]}
    assert err == []
    ctx.close()


def test_planification_bascule_et_enregistre_avec_les_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/reporter/", API)
    p.click("#o-planification"); p.wait_for_selector("#lPlan .plan")
    assert "0 6 * * *" in p.inner_text("#lPlan") and "INACTIVE" in p.inner_text("#lPlan")
    p.locator("#lPlan .inter input").check()
    p.wait_for_function("document.getElementById('rPlan').textContent.includes('activée')")
    posts = [json.loads(a[2]) for a in appels if a[0] == "POST" and a[1] == "/schedule"]
    assert posts == [{"report_type": "daily", "format": "pdf", "cron": "0 6 * * *", "enabled": True}]
    p.select_option("#pType", "network"); p.click("#presets button >> nth=3"); p.uncheck("#pActive")
    p.click("#fPlan button[type=submit]")
    p.wait_for_function("document.getElementById('rPlan').textContent.includes('enregistrée')")
    posts = [json.loads(a[2]) for a in appels if a[0] == "POST" and a[1] == "/schedule"]
    assert posts[-1] == {"report_type": "network", "format": "pdf", "cron": "0 */6 * * *", "enabled": False}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/reporter/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tOk", "#tAtt", "#tKo")] == ["—"] * 4
    assert p.url.startswith("http://sbx.test/reporter/") and err == []     # plus de redirection forcée vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/reporter/?demo=1", {})
    p.wait_for_selector("#bRap tr td.act", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bRap tr").first.get_by_text("Supprimer").click(); p.locator("#bRap tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRap').textContent.includes('inerte')")
    p.click("#o-generer"); p.click("#fGen button[type=submit]")
    p.wait_for_function("document.getElementById('rGen').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/reporter/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bRap tr td.act", state="attached")
    for onglet in ("o-generer", "o-planification", "o-rapports"):
        p.click("#" + onglet)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
