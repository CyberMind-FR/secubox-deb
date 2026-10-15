# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2765 — /grafana/ devient « Courbes » : historique réactif (plage, survol synchronisé, zoom au glissé) sans Grafana.

Vrai navigateur, API simulée. `?cadence=` (ms, plancher 300) règle l'actualisation pour les tests. Remplace test_grafana_aurora_2649 (l'ancienne page n'existe plus)."""
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "composants" / "grafana" / "www" / "grafana" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
N = 60


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def serie(n=N, trou=None, fin=1_000_000.0, duree=3600.0):
    pas = duree / n
    t = [fin - duree + (i + .5) * pas for i in range(n)]
    cpu = [20.0 + 30.0 * (i / n) for i in range(n)]
    if trou is not None:
        cpu[trou] = None
    return {"t": t, "pas_s": pas, "duree_s": duree, "points": n, "releve_s": 60,
            "series": {"cpu": cpu, "mem": [40.0 + i / 10 for i in range(n)], "charge": [1.0 + (i % 5) / 10 for i in range(n)],
                       "rx": [1_000_000.0 * (1 + i % 3) for i in range(n)], "tx": [200_000.0 for _ in range(n)],
                       "conn": [10 + i % 7 for i in range(n)], "disque": [61.0 for _ in range(n)]}}


def vide(n=N):
    s = serie(n)
    s["points"] = 0
    s["series"] = {k: [None] * n for k in s["series"]}
    return s


def ouvre(navigateur, reponse, statut=200, taille=None, reduit=False, cadence=60000):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900}, reduced_motion="reduce" if reduit else "no-preference")
    p = ctx.new_page()
    err, appels = [], []
    p.on("pageerror", lambda e: err.append(str(e)))
    p.route("http://sbx.test/grafana/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))

    def api(r, *_):
        q = {k: v[0] for k, v in parse_qs(urlparse(r.request.url).query).items()}
        appels.append(q)
        if statut != 200:
            r.fulfill(status=statut, content_type="application/json", body="{}")
            return
        r.fulfill(status=200, content_type="application/json", body=json.dumps(reponse(q) if callable(reponse) else reponse))
    p.route("http://sbx.test/api/v1/metrics/series*", api)
    p.goto(f"http://sbx.test/grafana/?cadence={cadence}")
    return ctx, p, err, appels


def test_six_courbes_et_la_plage_par_defaut_est_une_heure(navigateur):
    ctx, p, err, appels = ouvre(navigateur, serie())
    try:
        p.wait_for_selector(".courbe path.ligne")
        assert p.locator(".courbe").count() == 6
        assert appels[0]["duree"] == "3600" and int(appels[0]["points"]) >= 60
        assert p.locator('#plages button[aria-pressed="true"]').inner_text().strip() == "1 h"
        assert "EN DIRECT" in p.inner_text("#etat").upper() and not err
    finally:
        ctx.close()


@pytest.mark.parametrize("libelle,duree", [("15 min", "900"), ("6 h", "21600"), ("24 h", "86400"), ("7 j", "604800")])
def test_changer_de_plage_redemande_la_bonne_fenetre(navigateur, libelle, duree):
    ctx, p, err, appels = ouvre(navigateur, serie())
    try:
        p.wait_for_selector(".courbe path.ligne")
        p.click(f'#plages button:text-is("{libelle}")')
        p.wait_for_function(f"window.__n = 1; true")
        p.wait_for_timeout(300)
        assert appels[-1]["duree"] == duree
        assert p.locator('#plages button[aria-pressed="true"]').inner_text().strip() == libelle
    finally:
        ctx.close()


def test_min_moyenne_max_de_chaque_courbe(navigateur):
    ctx, p, err, _ = ouvre(navigateur, serie())
    try:
        p.wait_for_selector(".courbe path.ligne")
        txt = p.locator('.courbe[data-id="cpu"] .stats').inner_text()
        assert "20" in txt and "49" in txt and "min" in txt.lower() and "max" in txt.lower()
    finally:
        ctx.close()


def test_une_valeur_absente_fait_un_trou_pas_un_zero(navigateur):
    ctx, p, err, _ = ouvre(navigateur, serie(trou=30))
    try:
        p.wait_for_selector('.courbe[data-id="cpu"] path.ligne')
        d = p.locator('.courbe[data-id="cpu"] path.ligne').first.get_attribute("d")
        assert d.count("M") == 2, "deux segments autour du trou"
    finally:
        ctx.close()


def test_le_survol_affiche_toutes_les_valeurs_et_synchronise_les_courbes(navigateur):
    ctx, p, err, _ = ouvre(navigateur, serie())
    try:
        p.wait_for_selector(".courbe path.ligne")
        zone = p.locator('.courbe[data-id="cpu"] .zone')
        b = zone.bounding_box()
        p.mouse.move(b["x"] + b["width"] * 0.5, b["y"] + b["height"] / 2)
        p.wait_for_function("!document.querySelector('#lecture').hidden && document.querySelector('#lecture').textContent.length > 10")
        txt = p.inner_text("#lecture")
        assert "Processeur" in txt and "%" in txt and "↓" in txt
        visibles = p.locator(".courbe .repere:visible").count()
        assert visibles == 6, "le repère suit sur les six courbes"
    finally:
        ctx.close()


def test_glisser_sur_une_courbe_zoome_sur_l_intervalle(navigateur):
    ctx, p, err, appels = ouvre(navigateur, serie())
    try:
        p.wait_for_selector(".courbe path.ligne")
        b = p.locator('.courbe[data-id="mem"] .zone').bounding_box()
        y = b["y"] + b["height"] / 2
        p.mouse.move(b["x"] + b["width"] * 0.25, y)
        p.mouse.down()
        p.mouse.move(b["x"] + b["width"] * 0.55, y, steps=6)
        p.mouse.up()
        p.wait_for_function("window.__attend = true")
        p.wait_for_timeout(400)
        q = appels[-1]
        assert "depuis" in q and "jusqua" in q and float(q["jusqua"]) > float(q["depuis"])
        assert "ZOOM" in p.inner_text("#etat").upper()
        p.click("#tout")
        p.wait_for_timeout(400)
        assert "duree" in appels[-1] and "depuis" not in appels[-1]
    finally:
        ctx.close()


def test_un_simple_clic_ne_zoome_pas(navigateur):
    ctx, p, err, appels = ouvre(navigateur, serie())
    try:
        p.wait_for_selector(".courbe path.ligne")
        n = len(appels)
        b = p.locator('.courbe[data-id="cpu"] .zone').bounding_box()
        p.mouse.click(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
        p.wait_for_timeout(300)
        assert len(appels) == n
    finally:
        ctx.close()


def test_historique_vide_explique_le_releve_par_minute(navigateur):
    ctx, p, err, _ = ouvre(navigateur, vide())
    try:
        p.wait_for_function("document.querySelector('#vide') && !document.querySelector('#vide').hidden")
        assert "minute" in p.inner_text("#vide").lower()
        assert not err
    finally:
        ctx.close()


def test_une_panne_dit_reconnexion_et_ne_leve_pas(navigateur):
    ctx, p, err, _ = ouvre(navigateur, serie(), statut=503)
    try:
        p.wait_for_timeout(800)
        assert "RECONNEXION" in p.inner_text("#etat").upper() and not err
    finally:
        ctx.close()


def test_actualisation_automatique(navigateur):
    ctx, p, err, appels = ouvre(navigateur, serie(), cadence=500)
    try:
        p.wait_for_selector(".courbe path.ligne")
        p.wait_for_timeout(1700)
        assert len(appels) >= 3
    finally:
        ctx.close()


def test_pas_d_actualisation_pendant_un_zoom(navigateur):
    ctx, p, err, appels = ouvre(navigateur, serie(), cadence=500)
    try:
        p.wait_for_selector(".courbe path.ligne")
        b = p.locator('.courbe[data-id="cpu"] .zone').bounding_box()
        y = b["y"] + b["height"] / 2
        p.mouse.move(b["x"] + b["width"] * .2, y)
        p.mouse.down()
        p.mouse.move(b["x"] + b["width"] * .6, y, steps=5)
        p.mouse.up()
        p.wait_for_timeout(600)
        n = len(appels)
        p.wait_for_timeout(1500)
        assert len(appels) == n, "un zoom est une fenêtre figée"
    finally:
        ctx.close()


def test_mouvement_reduit_pas_d_animation_de_trace(navigateur):
    ctx, p, err, _ = ouvre(navigateur, serie(), reduit=True)
    try:
        p.wait_for_selector(".courbe path.ligne")
        for n in p.locator(".courbe path.ligne").evaluate_all("els => els.map(e => getComputedStyle(e).animationName)"):
            assert n == "none"
    finally:
        ctx.close()


def test_telephone_pas_de_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, serie(), taille={"width": 390, "height": 800})
    try:
        p.wait_for_selector(".courbe path.ligne")
        assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    finally:
        ctx.close()


def test_demonstration_sans_api(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    p.route("http://sbx.test/grafana/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.goto("http://sbx.test/grafana/?demo=1")
    try:
        p.wait_for_selector(".courbe path.ligne")
        assert not p.locator("#demo").is_hidden() and p.locator(".courbe").count() == 6
    finally:
        ctx.close()


def test_hygiene_de_la_page():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<link[^>]+href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    assert not re.search(r"<script[^>]+src=", SRC) and "fonts.googleapis" not in SRC
    assert "lorem" not in SRC.lower() and "'POST'" not in SRC
    assert "sbx_token" in SRC and "/api/v1/metrics/series" in SRC
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in SRC
