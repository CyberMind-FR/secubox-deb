# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2989 — page /metrics/ : la carte « Connexions en direct » est retirée (demande explicite, redondante avec
Attaques/Visiteurs), et ces deux-là reçoivent un flash lumineux (pas sonore) quand un pays augmente, en plus du
pulse existant (#2763)."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "metrics" / "index.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, waf_series, vhost_series=None):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.route("http://sbx.test/metrics/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    n = {"waf": 0, "vhost": 0}

    def waf(r, *_):
        body = waf_series[min(n["waf"], len(waf_series) - 1)]
        n["waf"] += 1
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"top_countries": body}))

    def vhost(r, *_):
        serie = vhost_series or [{}]
        pays = serie[min(n["vhost"], len(serie) - 1)]
        n["vhost"] += 1
        body = {"du": "2026-10-14", "au": "2026-10-20", "vhosts": [{"vhost": "www.exemple.test", "pays": [{"code": k, "n": v} for k, v in pays.items()]}]}
        r.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    p.route("http://sbx.test/api/**", lambda r, *_: r.fulfill(status=404, content_type="application/json", body="{}"))
    p.route("http://sbx.test/api/v1/metrics/waf_stats", waf)
    p.route("http://sbx.test/api/v1/metrics/vhost-stats*", vhost)
    p.goto("http://sbx.test/metrics/?cadence=60000")
    return ctx, p, erreurs


def test_la_carte_en_direct_n_existe_plus(navigateur):
    ctx, p, err = ouvre(navigateur, [{"CN": 10}])
    try:
        p.wait_for_selector("#mondeAtt circle")
        assert p.locator("#panLive").count() == 0
        assert p.locator("#mondeLive").count() == 0
        assert not err
    finally:
        ctx.close()


def test_les_cartes_attaques_et_visiteurs_restent(navigateur):
    ctx, p, _ = ouvre(navigateur, [{"CN": 10}])
    try:
        assert p.locator("#mondeAtt").count() == 1 and p.locator("#mondeVis").count() == 1
    finally:
        ctx.close()


def test_un_pays_qui_augmente_recoit_un_flash_lumineux_sur_attaques(navigateur):
    ctx, p, err = ouvre(navigateur, [{"CN": 10, "RU": 5}, {"CN": 25, "RU": 5}])
    try:
        p.wait_for_selector("#mondeAtt circle")
        p.click("#rafraichir")
        p.wait_for_selector("#mondeAtt circle.flash", timeout=8000)
        assert p.locator("#mondeAtt circle.flash").count() == 1, "seulement la Chine (RU est stable)"
        assert p.locator("#mondeAtt circle.flash").first.get_attribute("fill") == "#fff"
        assert p.locator("#mondeAtt circle.ping").count() == 1, "le pulse existant (#2763) reste en plus du flash"
        assert not err
    finally:
        ctx.close()


def test_un_pays_qui_augmente_recoit_un_flash_lumineux_sur_visiteurs(navigateur):
    ctx, p, err = ouvre(navigateur, [{"FR": 100}], [{"FR": 100}, {"FR": 400}])
    try:
        p.wait_for_selector("#mondeVis circle")
        p.click("#rafraichir")
        p.wait_for_selector("#mondeVis circle.flash", timeout=8000)
        assert p.locator("#mondeVis circle.flash").count() >= 1
        assert not err
    finally:
        ctx.close()


def test_rien_ne_flashe_a_la_premiere_mesure_ni_si_rien_ne_change(navigateur):
    ctx, p, _, = ouvre(navigateur, [{"CN": 10}] * 3)
    try:
        p.wait_for_selector("#mondeAtt circle")
        p.wait_for_timeout(500)
        assert p.locator("#mondeAtt circle.flash").count() == 0
    finally:
        ctx.close()


def test_mouvement_reduit_pas_d_animation_sur_le_flash(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900}, reduced_motion="reduce")
    p = ctx.new_page()
    p.route("http://sbx.test/metrics/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    n = {"i": 0}

    def waf(r, *_):
        n["i"] += 1
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"top_countries": {"CN": 10 if n["i"] == 1 else 25}}))
    p.route("http://sbx.test/api/**", lambda r, *_: r.fulfill(status=404, content_type="application/json", body="{}"))
    p.route("http://sbx.test/api/v1/metrics/waf_stats", waf)
    p.goto("http://sbx.test/metrics/?cadence=60000")
    try:
        p.wait_for_selector("#mondeAtt circle")
        p.click("#rafraichir")
        p.wait_for_selector("#mondeAtt circle.flash", timeout=8000)
        for n_ in p.locator("#mondeAtt circle.flash").evaluate_all("els => els.map(e => getComputedStyle(e).animationName)"):
            assert n_ == "none"
    finally:
        ctx.close()
