# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2646 — pages de la posture de sécurité au profil Aurora : statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www"
PAGE = (WWW / "security-posture" / "index.html").read_text(encoding="utf-8")
TABLEAU = (WWW / "index.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("src,onglet", [(PAGE, "security-posture"), (TABLEAU, "security-posture-tableau")])
def test_pages_autonomes_sans_dialogue_natif(src, onglet):
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in src
    assert re.findall(r'<script src="([^"]+)"', src) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in src and "googleapis" not in src and "gstatic" not in src
    assert "<link" in src and not re.search(r'<link[^>]+href="(?!/shared/sidebar-light\.css)', src)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML"):
        assert interdit not in src
    assert "lorem" not in src.lower() and "Math.random" not in src and "setItem" not in src
    assert "sbxVue" in src and ("onglet: '%s'" % onglet) in src and "demo" in src.lower() and "embed" in src
    assert "localStorage.getItem('sbx_token')" in src


def test_routes_a_l_identique():
    assert "lire('/overview')" in PAGE and "API + '/refresh'" in PAGE and "method: 'POST'" in PAGE
    assert not (WWW / "security-posture" / "posture.js").exists() and not (WWW / "security-posture" / "posture.css").exists()
    for r in ("'/overview'", "'/defcon'", "'/cspn/summary'", "'/tpn/summary'", "'/performance/summary'"):
        assert "lire(" + r in TABLEAU
    assert "POST" not in TABLEAU


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


SNAP = {
    "timestamp": "2026-10-14T10:00:00+00:00", "coverage": 0.6,
    "overall": {"score": 72.4, "level": 3, "name": "Attention", "color": "#ff9f1c", "emoji": "🟠", "blink": False},
    "domains": [{"domain": "wall", "name": "Pare-feu <i>x</i>", "icon": "🛡️", "color": "#2ecc71", "link": "/waf/", "blurb": "nftables",
                 "score": 81, "coverage": 0.9,
                 "indicators": [{"status": "warn", "label": "Règles anciennes", "detail": "12 jours", "value": 0.6},
                                {"status": "unknown", "label": "Audit", "detail": "", "value": None}]},
                {"domain": "root", "name": "Système", "icon": "🧬", "color": "javascript:alert(1)", "link": "javascript:alert(1)", "blurb": "",
                 "score": None, "coverage": 0, "indicators": []}],
    "findings": [{"severity": "crit", "title": "Mises à jour", "domain": "Système", "link": "/antirootkit/", "detail": "4 paquets", "remediation": "apt-get -s upgrade"}],
    "cspn": {"score": 75.0, "passed": 3, "scored": 4, "manual": 1, "items": [{"id": "C1", "title": "Exigence un", "detail": "d", "status": "pass"}, {"id": "C2", "title": "Deux", "detail": "", "status": "fail"}]},
    "tpn": {"score": None, "passed": 0, "scored": 0, "manual": 2, "items": [{"id": "T1", "title": "Médias", "detail": "", "status": "manual"}]},
}
API = {"/overview": (200, SNAP)}
URL = "http://sbx.test/security-posture/"
URL_T = "http://sbx.test/tableau/"


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', '%s')" % jeton)
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "security-posture":
            r.fulfill(status=200, content_type="text/html", body=PAGE)
        elif chemin.rstrip("/") == "tableau":
            r.fulfill(status=200, content_type="text/html", body=TABLEAU)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/security-posture", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.headers.get("authorization")))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"status": "refreshed"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/security-posture/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_domaines_constats_et_audits_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API, jeton="jt")
    p.wait_for_selector("#domaines .dom", state="attached")
    assert [p.inner_text(i) for i in ("#tScore", "#tDefcon", "#tCouv", "#tConstats", "#tCspn", "#tTpn")] == ["72", "3", "60 %", "1", "75 %", "—"]
    assert p.inner_text("#etat") == "DEFCON 3" and p.inner_text("#dNom") == "Attention"
    assert p.locator("#domaines .dom").count() == 2 and "<i>x</i>" in p.inner_text("#domaines") and p.locator("#domaines .nm i").count() == 0
    assert p.inner_text("#domaines .dom >> nth=1 >> .sc") == "—"                      # pas de mesure : « — », jamais 0
    assert p.locator("#domaines a[href^='javascript']").count() == 0 and p.locator("#constats a[href^='/antirootkit']").count() == 1
    assert "apt-get -s upgrade" in p.inner_text("#constats") and "échec" in p.inner_text("#bCspn")
    assert p.inner_text("#tpnPill") == "2 manuelle(s)" and "manuel" in p.inner_text("#bTpn")
    assert {a[2] for a in appels} == {"Bearer jt"} and err == []
    ctx.close()


def test_recalculer_envoie_post_refresh_avec_jeton(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API, jeton="jt")
    p.wait_for_selector("#domaines .dom", state="attached")
    p.click("#btnRecalc")
    p.wait_for_function("document.getElementById('rRecalc').textContent.includes('recalculée')")
    assert ("POST", "/refresh", "Bearer jt") in appels
    ctx.close()


def test_calcul_en_cours_503(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {"/overview": (503, {"detail": "posture not computed yet"})})
    p.wait_for_selector("#calcul:not([hidden])")
    assert p.inner_text("#etat") == "CALCUL EN COURS" and p.inner_text("#tScore") == "—" and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {"/overview": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tScore", "#tDefcon", "#tCouv", "#tConstats", "#tCspn", "#tTpn")] == ["—"] * 6 and err == []
    ctx.close()


def test_service_arrete_hors_ligne(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {"/overview": (500, {})})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert not p.is_hidden("#erreur") and err == []
    ctx.close()


def test_demonstration_annoncee_et_action_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#domaines .dom", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnRecalc")
    p.wait_for_function("document.getElementById('rRecalc').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#domaines .dom", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


# ---- Tableau historique (www/index.html) ----
LEGACY = {"/overview": (200, {"recommendations": [{"severity": "high", "text": "<b>Patch</b>"}]}),
          "/defcon": (200, {"level_name": "DEFCON 4", "score": 91.25, "color": "#22c55e", "category_scores": {"Auth": 90.0}}),
          "/cspn/summary": (200, {"summary": {"compliance_score": 80, "is_compliant": True, "total_requirements": 5, "passed": 4, "failed": 1}}),
          "/tpn/summary": (200, {"summary": {"compliance_score": 40, "is_compliant": False}}),
          "/performance/summary": (200, {"score": 66.0, "category_scores": {"Latence": 70}})}


def test_tableau_historique_garde_ses_cinq_appels(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL_T, LEGACY, jeton="jt")
    p.wait_for_function("document.getElementById('tPerf').textContent !== '—'")
    assert sorted(a[1] for a in appels) == ["/cspn/summary", "/defcon", "/overview", "/performance/summary", "/tpn/summary"]
    assert {a[0] for a in appels} == {"GET"} and {a[2] for a in appels} == {"Bearer jt"}
    assert [p.inner_text(i) for i in ("#tDefcon", "#tCspn", "#tTpn", "#tPerf")] == ["DEFCON 4", "80,0 %", "40,0 %", "66,0 %"]
    assert "<b>Patch</b>" in p.inner_text("#recos") and p.locator("#recos b").count() == 0
    assert "Total" in p.inner_text("#cspnStats") and p.inner_text("#etat") == "EN LIGNE" and err == []
    ctx.close()


def test_tableau_route_absente_laisse_un_tiret(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL_T, {"/overview": (200, {"recommendations": []})})
    p.wait_for_function("document.getElementById('etat').textContent === 'EN LIGNE'")
    assert [p.inner_text(i) for i in ("#tDefcon", "#tCspn", "#tTpn", "#tPerf")] == ["—"] * 4
    assert "optimaux" in p.inner_text("#recos") and err == []
    ctx.close()


def test_tableau_sans_session_demo_et_telephone(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL_T, {k: (401, {}) for k in LEGACY})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and p.inner_text("#tCspn") == "—" and err == []
    ctx.close()
    ctx, p, err, appels = ouvre(navigateur, URL_T + "?demo=1&embed=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tPerf').textContent !== '—'")
    assert p.is_visible("#demo") and appels == [] and err == []
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    ctx.close()
