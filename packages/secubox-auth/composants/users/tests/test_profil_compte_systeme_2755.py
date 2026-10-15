# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2755 — la page /users/ montre à quel profil SBX OS chaque compte système est associé, et permet de le modifier.

Vrai navigateur, API simulée (banc de test_users_aurora_2571). L'API d'association existe déjà côté sbxid :
GET /admin/comptes-systeme, PUT /admin/personnes/{uuid}/compte-systeme, DELETE …/compte-systeme/{compte}."""
import json

import pytest

from test_users_aurora_2571 import ROUTES, navigateur, ouvre  # noqa: F401

pytest.importorskip("playwright.sync_api")

U1, U2 = "a1b2c3d4-0000", "e5f6a7b8-0000"
PERSONNES = {"personnes": [
    {"user_uuid": U1, "pseudo": "gandalf", "tier": "free", "status": "active", "roles": ["member"], "appareils": 2, "liens": {"systeme": ["admin"]}},
    {"user_uuid": U2, "pseudo": "frodon", "tier": "free", "status": "active", "roles": ["guest"], "appareils": 1, "liens": {}},
    {"user_uuid": "x", "pseudo": "suspendu", "tier": "free", "status": "suspended", "roles": [], "appareils": 0, "liens": {}}]}
LIENS = {"liens": [{"compte": "admin", "user_uuid": U1, "pseudo": "gandalf"}]}
CHEMIN_LIENS = ("GET", "/api/v1/sbxid/admin/comptes-systeme")


def routes(liens=(200, LIENS), extra=None):
    r = dict(ROUTES)
    r[("GET", "/api/v1/sbxid/admin/personnes")] = (200, PERSONNES)
    r[CHEMIN_LIENS] = liens
    r.update(extra or {})
    return r


def ouvrir(nav, **kw):
    ctx, p, err, appels = ouvre(nav, "http://sbx.test/users/", routes(**kw))
    p.wait_for_selector("#bComptes tr", state="attached")
    return ctx, p, err, appels


def ligne(p, nom):
    return p.locator("#bComptes tr", has_text=nom).first


def ecritures(appels):
    return [(m, c, json.loads(b) if b else None) for m, c, b in appels if m in ("PUT", "DELETE") and "compte-systeme" in c]


def test_la_colonne_montre_le_profil_associe(navigateur):
    ctx, p, err, _ = ouvrir(navigateur)
    try:
        assert "profil sbx os" in p.locator("#t-comptes thead").inner_text().lower()
        assert "gandalf" in ligne(p, "admin").inner_text()
        assert "non associé" in ligne(p, "jdupont").inner_text().lower()
        assert not err
    finally:
        ctx.close()


def test_sans_droit_d_administrateur_systeme_la_colonne_dit_pourquoi_sans_fausse_donnee(navigateur):
    ctx, p, err, _ = ouvrir(navigateur, liens=(403, {"detail": "Réservé à un administrateur système"}))
    try:
        txt = ligne(p, "admin").inner_text()
        assert "gandalf" not in txt and "non associé" not in txt.lower(), "ne pas affirmer « non associé » quand on ne sait pas"
        assert ligne(p, "admin").locator("button[data-profil]").count() == 0
    finally:
        ctx.close()


def test_associer_un_compte_non_associe(navigateur):
    ctx, p, err, appels = ouvrir(navigateur)
    try:
        ligne(p, "jdupont").locator("button[data-profil]").click()
        p.select_option("#bComptes select[data-profil-choix]", label="frodon")
        p.locator("#bComptes button[data-profil-ok]").click()
        p.wait_for_function("document.querySelector('#rComptes') && !document.querySelector('#rComptes').hidden")
        assert ecritures(appels) == [("PUT", f"/api/v1/sbxid/admin/personnes/{U2}/compte-systeme", {"compte": "jdupont"})]
    finally:
        ctx.close()


def test_changer_de_profil_delie_l_ancien_puis_lie_le_nouveau(navigateur):
    """Le serveur refuse un compte déjà lié à une autre personne : l'ordre compte."""
    ctx, p, err, appels = ouvrir(navigateur)
    try:
        ligne(p, "admin").locator("button[data-profil]").click()
        p.select_option("#bComptes select[data-profil-choix]", label="frodon")
        p.locator("#bComptes button[data-profil-ok]").click()
        p.wait_for_function("document.querySelector('#rComptes') && !document.querySelector('#rComptes').hidden")
        assert ecritures(appels) == [("DELETE", f"/api/v1/sbxid/admin/personnes/{U1}/compte-systeme/admin", None),
                                     ("PUT", f"/api/v1/sbxid/admin/personnes/{U2}/compte-systeme", {"compte": "admin"})]
    finally:
        ctx.close()


def test_dissocier(navigateur):
    ctx, p, err, appels = ouvrir(navigateur)
    try:
        ligne(p, "admin").locator("button[data-profil]").click()
        p.select_option("#bComptes select[data-profil-choix]", value="")
        p.locator("#bComptes button[data-profil-ok]").click()
        p.wait_for_function("document.querySelector('#rComptes') && !document.querySelector('#rComptes').hidden")
        assert ecritures(appels) == [("DELETE", f"/api/v1/sbxid/admin/personnes/{U1}/compte-systeme/admin", None)]
    finally:
        ctx.close()


def test_un_echec_du_nouveau_lien_restaure_l_ancien_et_le_dit(navigateur):
    ctx, p, err, appels = ouvrir(navigateur, extra={("PUT", f"/api/v1/sbxid/admin/personnes/{U2}/compte-systeme"): (409, {"detail": "« admin » n'est pas un compte d'administration ouvert"})})
    try:
        ligne(p, "admin").locator("button[data-profil]").click()
        p.select_option("#bComptes select[data-profil-choix]", label="frodon")
        p.locator("#bComptes button[data-profil-ok]").click()
        p.wait_for_function("document.querySelector('#rComptes') && !document.querySelector('#rComptes').hidden")
        e = ecritures(appels)
        assert e[-1] == ("PUT", f"/api/v1/sbxid/admin/personnes/{U1}/compte-systeme", {"compte": "admin"}), "l'ancien lien doit être remis"
        assert "ko" in p.locator("#rComptes").get_attribute("class") and "administration" in p.locator("#rComptes").inner_text()
    finally:
        ctx.close()


def test_une_personne_suspendue_n_est_pas_proposee(navigateur):
    ctx, p, err, _ = ouvrir(navigateur)
    try:
        ligne(p, "jdupont").locator("button[data-profil]").click()
        opts = p.locator("#bComptes select[data-profil-choix] option").all_inner_texts()
        assert "suspendu" not in opts and "gandalf" in opts and "frodon" in opts
    finally:
        ctx.close()


def test_aucune_modification_sans_choix_different(navigateur):
    ctx, p, err, appels = ouvrir(navigateur)
    try:
        ligne(p, "admin").locator("button[data-profil]").click()
        p.locator("#bComptes button[data-profil-ok]").click()
        assert ecritures(appels) == []
    finally:
        ctx.close()
