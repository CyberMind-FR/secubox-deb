# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2808 — /appstore/ : panneau « Installation à distance » (demander, décider, suivre), accord par retape du nom, DOM sûr."""
import json

import pytest

import test_appstore_aurora_2571 as base
from test_appstore_aurora_2571 import navigateur, ouvre, SRC  # noqa: F401

pytest.importorskip("playwright.sync_api")

REMOTE = {"boite": "ok",
          "recues": [{"id": "m1", "demande": "e" * 32, "de": "did:plc:" + "a" * 32, "boxname": "gk3", "paquet": "secubox-radio", "emis": 1000, "etat": "en_attente", "message": ""},
                     {"id": "m2", "demande": "f" * 32, "de": "did:plc:" + "a" * 32, "boxname": "gk3", "paquet": "secubox-dns", "emis": 900, "etat": "installee", "message": "installé"}],
          "envoyees": [{"id": "d1", "a": "did:plc:" + "b" * 32, "boxname": "gk2", "paquet": "secubox-relais", "emis": 800, "etat": "refusee", "message": ""}]}


@pytest.fixture()
def avec_remote(monkeypatch):
    monkeypatch.setitem(base.LECTURES, "/remote/demandes", REMOTE)


def ouvrir(navigateur, ecritures=None):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/appstore/", ecritures=ecritures)
    p.wait_for_selector("#bRecues tr")
    return ctx, p, err, appels


def test_les_demandes_recues_et_envoyees_s_affichent(navigateur, avec_remote):
    ctx, p, err, _ = ouvrir(navigateur)
    assert "gk3" in p.inner_text("#bRecues") and "secubox-radio" in p.inner_text("#bRecues") and "secubox-dns" in p.inner_text("#bRecues")
    assert "installé" in p.inner_text("#bRecues").lower()
    assert "gk2" in p.inner_text("#bEnvoyees") and "refusée" in p.inner_text("#bEnvoyees").lower()
    assert err == []
    ctx.close()


def test_accepter_exige_de_retaper_le_nom_puis_appelle_la_route(navigateur, avec_remote):
    ctx, p, err, appels = ouvrir(navigateur)
    ligne = p.locator("#bRecues tr", has_text="secubox-radio")
    bouton = ligne.locator("button[data-action=accepter]")
    assert bouton.is_disabled()
    ligne.locator("input").fill("secubox-autre")
    assert bouton.is_disabled()
    ligne.locator("input").fill("secubox-radio")
    assert not bouton.is_disabled()
    bouton.click()
    p.wait_for_timeout(300)
    assert any(m == "POST" and u == "/api/v1/appstore/remote/demandes/m1/accepter" and "confirmer=secubox-radio" in (q or "") for m, u, q, *_ in appels) or \
        any("/remote/demandes/m1/accepter" in u for _, u, *_ in appels)
    ctx.close()


def test_une_demande_deja_traitee_n_a_pas_de_bouton(navigateur, avec_remote):
    ctx, p, err, _ = ouvrir(navigateur)
    assert p.locator("#bRecues tr", has_text="secubox-dns").locator("button").count() == 0
    ctx.close()


def test_refuser_appelle_la_route(navigateur, avec_remote):
    ctx, p, err, appels = ouvrir(navigateur)
    p.locator("#bRecues tr", has_text="secubox-radio").locator("button[data-action=refuser]").click()
    p.wait_for_timeout(300)
    assert any("/remote/demandes/m1/refuser" in u for _, u, *_ in appels)
    ctx.close()


def test_demander_poste_le_noeud_et_le_paquet(navigateur, avec_remote):
    ctx, p, err, appels = ouvrir(navigateur)
    p.wait_for_selector("#rPair option[value=sat-a]", state="attached") if False else None
    p.fill("#rPair", "gk2")
    p.fill("#rPaquet", "secubox-relais")
    p.click("#rEnvoyer")
    p.wait_for_timeout(300)
    posts = [a for a in appels if a[0] == "POST" and a[1].endswith("/remote/demander")]
    assert posts and json.loads(posts[0][2]) == {"pair": "gk2", "paquet": "secubox-relais"}
    ctx.close()


def test_une_boite_indisponible_est_dite(navigateur, monkeypatch):
    monkeypatch.setitem(base.LECTURES, "/remote/demandes", dict(REMOTE, boite="indisponible"))
    ctx, p, err, _ = ouvrir(navigateur)
    assert "indisponible" in p.inner_text("#rRemote").lower() or "indisponible" in p.inner_text("#pRemote").lower()
    ctx.close()


def test_donnees_d_api_jamais_interpretees_en_html(navigateur, monkeypatch):
    piege = dict(REMOTE, recues=[dict(REMOTE["recues"][0], boxname="<img src=x onerror=window.PWNED=1>")])
    monkeypatch.setitem(base.LECTURES, "/remote/demandes", piege)
    ctx, p, err, _ = ouvrir(navigateur)
    assert "<img src=x" in p.inner_text("#bRecues") and p.evaluate("window.PWNED === undefined")
    ctx.close()
