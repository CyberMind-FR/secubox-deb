# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2651 — /devwatch/ au profil Aurora : test statique + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "devwatch" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "gstatic" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'devwatch'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_lecture_seule_memes_routes():
    assert "lire('/summary')" in SRC and "lire('/issues')" in SRC
    assert "method:" not in SRC and "POST" not in SRC and "DELETE" not in SRC
    assert 'href="admin.html"' in SRC                     # le lien vers l'admin reste, admin.html n'est pas touché
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC and "try {" in SRC
    assert "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def iso(heures):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - heures * 3600))


SUMMARY = {
    "ok": True, "repo": {"full": "exemple-org/depot", "html_url": "https://example.org/exemple-org/depot"},
    "totals": {"commits": 1842, "contributors": 6, "releases": 0, "tags": 22, "stars": 318, "forks": 41, "open_issues": 27, "open_prs": 3},
    "cadence": {"today": 0, "last7": 33, "per_day": 4.7, "daily": [2, 5, 3, 0, 1, 6, 4, 7, 3, 2, 0, 0, 5, 8, 6, 4, 3, 1, 0, 2, 5, 9, 7, 4, 3, 2, 6, 8, 5, 4],
                "arrows": {"weekly": {"value": 33, "good": "up", "dir": "up", "pct": 12.5}, "commits_per_day": {"value": 4.7, "good": "up", "dir": "down", "pct": -8.0},
                           "review_latency": {"value": 5.2, "good": "down", "dir": "flat", "pct": 0.0}, "release_cadence": {"value": 0.4, "good": "up", "dir": "flat", "pct": 0.0}}},
    "emancipation": {"time": {"hours": 676, "days_dev": 28.2, "detail": "1842 commits × ~22 min"}, "cost": {"keur": 43.9, "detail": "676 h × 65 €/h"},
                     "carbon": {"co2_t": 0.1, "km_car": 21700, "detail": "CI + calcul + poste"}},
    "fund": {"pct": 18.0, "seeking": True, "sponsor_recu": 400, "depenses_cumulees": 2200},
    "latest_commits": [{"sha": "a1b2c3d", "login": "dev-exemple", "message": "<b>feat</b>: page", "date": iso(2)}],
    "latest_release": {"tag": "v1.4.0", "name": "Version 1.4.0", "url": "https://example.org/r/v1.4.0", "published_at": iso(100), "body": "<i>notes</i>"},
    "evolutions": [{"tag": "v1.0.0", "type": "major", "weight": 100, "url": "https://example.org/a", "gap_days": 0},
                   {"tag": "v1.4.0", "type": "minor", "weight": 60, "url": "javascript:alert(1)", "gap_days": 21, "latest": True}],
    "modules": {"total": 2, "modules": [{"name": "secubox-exemple", "version": "1.2.0-1", "dev": "Dev", "date": "2026-10-12"}, {"name": "secubox-demo", "version": "0.4.1-1", "dev": "Dev", "date": ""}]},
    "issues": [{"number": 12, "title": "Titre <u>piégé</u>", "prio": "hi", "labels": ["enhancement"], "url": "https://example.org/issues/12"}],
    "meta": {"rate_left": 4821, "error": None},
}
ISSUES = {"ok": True, "compte": {"ouvertes": 27, "en_cours": 2, "fermees": 310, "total": 337, "fermees_30j": 41, "ouvertes_7j": 5},
          "listes": {"ouvertes": [{"n": 12, "titre": "A", "labels": ["enhancement"], "url": "https://example.org/i/12", "maj": iso(5)}],
                     "en_cours": [{"n": 13, "titre": "B", "labels": ["wip"], "branche": True, "url": "https://example.org/i/13", "maj": iso(5)}],
                     "fermees": [{"n": 7, "titre": "C", "labels": [], "url": "https://example.org/i/7", "ferme": iso(50)}]},
          "par_etiquette": {"enhancement": 9, "docs": 5}, "delai_median_heures": 27.0, "delai_median_jours": 1.1, "plus_ancienne_jours": 119,
          "definition_en_cours": "une branche vivante ou wip", "echantillon_fermees": 1, "releve": iso(0)}
API = {"/summary": (200, SUMMARY), "/issues": (200, ISSUES)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token', '%s')" % jeton)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "devwatch":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/devwatch", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/devwatch/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_panneaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/devwatch/", API, jeton="jeton-de-test")
    p.wait_for_function("document.getElementById('tCommits').textContent !== '—'")
    assert p.inner_text("#etat") == "EN DIRECT" and p.inner_text("#depot") == "exemple-org/depot"
    assert p.inner_text("#tRel") == "0"                                   # 0 est une mesure
    assert p.inner_text("#tContrib") == "6" and p.inner_text("#tPr") == "3" and "318" in p.inner_text("#tStars")
    assert "0 aujourd" in p.inner_text("#sCommits")
    assert p.get_attribute("#tCommits >> xpath=..", "title") and p.get_attribute("#eTemps >> xpath=..", "title")
    assert "676" in p.inner_text("#eTemps") and "43" in p.inner_text("#eCout") and "18" in p.inner_text("#eFond")
    assert p.locator("#spark svg rect").count() == 30 and p.locator("#evoGraph svg rect").count() == 2
    assert p.locator("#modsList .mod").count() == 2 and p.locator("#chant .ch").count() == 1
    assert p.inner_text("#iOuv") == "27" and p.inner_text("#iCours") == "2"
    assert all(a[2] == "Bearer jeton-de-test" for a in appels) and {a[1] for a in appels} == {"/summary", "/issues"}
    assert all(a[0] == "GET" for a in appels) and err == []
    ctx.close()


def test_pas_de_tendance_inventee_et_texte_brut(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/devwatch/", API)
    p.wait_for_function("document.getElementById('tCommits').textContent !== '—'")
    effs = p.locator("#effrow .eff").all_inner_texts()
    assert "↘ -8 %" in effs[0] and "tendance non calculée" in effs[1] and "tendance non calculée" in effs[2] and "↗ +12.5 %" in effs[3]
    assert "<b>feat</b>" in p.inner_text("#commits") and p.locator("#commits b").count() == 0
    assert "<i>notes</i>" in p.inner_text("#release") and p.locator("#release i").count() == 0
    assert "<u>piégé</u>" in p.inner_text("#chant") and p.locator("#chant u").count() == 0
    # une adresse qui n'est pas https n'est jamais un lien
    assert p.locator("#evoGraph a").count() == 1 and err == []
    ctx.close()


def test_onglets_des_issues(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/devwatch/", API)
    p.wait_for_function("document.getElementById('iOuv').textContent === '27'")
    assert p.locator("#issList .ibar").count() == 2
    p.click("[data-e=en_cours]")
    assert p.locator("#issList .ir").count() == 1 and "branche" in p.inner_text("#issList") and "wip" in p.inner_text("#issNote")
    p.click("[data-e=fermees]")
    assert "fermée" in p.inner_text("#issList") and "sur 310" in p.inner_text("#issNote")
    assert p.get_attribute("[data-e=fermees]", "aria-selected") == "true" and err == []
    ctx.close()


def test_prechauffage_et_issues_absentes(navigateur):
    routes = {"/summary": (200, {"warming": True, "repo": {"full": "a/b"}}), "/issues": (200, {"ok": False})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/devwatch/", routes)
    p.wait_for_function("document.getElementById('etat').textContent === 'PRÉCHAUFFAGE'")
    assert p.inner_text("#tCommits") == "—" and p.inner_text("#iOuv") == "—" and "indisponible" in p.inner_text("#issSub") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/devwatch/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and "session requise" in p.inner_text("#session")
    assert [p.inner_text(i) for i in ("#tCommits", "#tContrib", "#tRel", "#tIss", "#tPr", "#tStars", "#eTemps", "#iOuv")] == ["—"] * 8
    assert p.url.endswith("/devwatch/") and err == []
    ctx.close()


def test_api_injoignable(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/devwatch/", {"/summary": (500, {}), "/issues": (500, {})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and err == []
    ctx.close()


def test_demonstration_annoncee(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/devwatch/?demo=1", {})
    p.wait_for_function("document.getElementById('tCommits').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert "exemple-org" in p.inner_text("#depot") and appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/devwatch/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('iOuv').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
