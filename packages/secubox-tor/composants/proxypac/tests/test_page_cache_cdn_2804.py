# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2804 — /proxypac/ : candidats détaillés, « Mettre en cache » pour un CDN statique, « Retirer » s'il l'est déjà, rien pour une API."""
import pytest

from test_proxypac_aurora_2556 import API, navigateur, ouvre, SRC  # noqa: F401

pytest.importorskip("playwright.sync_api")

CANDS = {"candidates": [
    {"host": "cdnjs.cloudflare.com", "hits": 120, "clients": 4, "famille": "cloudflare", "cacheable": True, "en_cache": False},
    {"host": "unpkg.com", "hits": 30, "clients": 2, "famille": "unpkg", "cacheable": True, "en_cache": True},
    {"host": "play.googleapis.com", "hits": 5235, "clients": 30, "famille": "google", "cacheable": False, "en_cache": False}]}
ROUTES = dict(API, **{"/candidates": (200, CANDS)})


def ligne(p, hote):
    return p.locator("#bCand tr", has_text=hote)


def test_chaque_candidat_montre_ses_mesures_et_la_bonne_action(navigateur):
    ctx, p, err, _, dlg = ouvre(navigateur, "http://sbx.test/proxypac/", ROUTES)
    p.wait_for_selector("#bCand tr")
    assert "120" in ligne(p, "cdnjs.cloudflare.com").inner_text() and "cloudflare" in ligne(p, "cdnjs.cloudflare.com").inner_text()
    assert ligne(p, "cdnjs.cloudflare.com").locator("button[data-action=cache]").count() == 1
    assert ligne(p, "unpkg.com").locator("button[data-action=decache]").count() == 1 and "En cache" in ligne(p, "unpkg.com").inner_text()
    assert ligne(p, "play.googleapis.com").locator("button").count() == 0 and "API" in ligne(p, "play.googleapis.com").inner_text()
    assert err == [] and dlg == []
    ctx.close()


def test_mettre_en_cache_appelle_la_route_et_recharge(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/proxypac/", ROUTES)
    p.wait_for_selector("#bCand tr")
    ligne(p, "cdnjs.cloudflare.com").locator("button[data-action=cache]").click()
    p.wait_for_timeout(300)
    assert ("POST", "/candidate/cdnjs.cloudflare.com/cache", None) in appels
    ctx.close()


def test_retirer_du_cache_appelle_delete(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/proxypac/", ROUTES)
    p.wait_for_selector("#bCand tr")
    ligne(p, "unpkg.com").locator("button[data-action=decache]").click()
    p.wait_for_timeout(300)
    assert ("DELETE", "/cdn-cache/unpkg.com", None) in appels
    ctx.close()


def test_une_raison_de_refus_est_affichee(navigateur):
    routes = dict(ROUTES, **{"/candidate/cdnjs.cloudflare.com/cache": (400, {"detail": "Hôte non statique"})})
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/proxypac/", routes)
    p.wait_for_selector("#bCand tr")
    ligne(p, "cdnjs.cloudflare.com").locator("button[data-action=cache]").click()
    p.wait_for_selector("#rCand:not([hidden])")
    assert "non statique" in p.inner_text("#rCand")
    ctx.close()
