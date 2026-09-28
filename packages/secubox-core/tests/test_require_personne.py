# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Plancher `require_personne` : la session d'une PERSONNE, profil user ou plus (#1607).

Trois étages de garde, du plus large au plus étroit :
  require_session  — n'importe quelle session reconnue, invités compris ;
  require_personne — une personne : compte actif, ou appareil admis user/admin ;
  require_jwt      — un administrateur réel (#1581).
"""
from __future__ import annotations

import pytest

from secubox_core import auth

HALL_ORIGINE = "https://hall.gk2.secubox.in"
# Les appareils inscrits par la fixture `box` (conftest.py), par profil.
GUEST, USER, ADMIN, REVOQUE = ("sbx-00000000000a", "sbx-00000000000b",
                               "sbx-00000000000c", "sbx-00000000000d")


def _post(box, client, tok, **entetes):
    return client.post("/diffuser", headers=box.cookie(tok, Origin=HALL_ORIGINE, **entetes))


# ── Qui passe ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("sub", ["alice", "gk2", USER, ADMIN])
def test_personne_admise(box, client, sub):
    r = _post(box, client, box.jeton(sub))
    assert r.status_code == 200, r.text
    assert r.json()["sub"] == sub


def test_admin_reel_admis_par_porteur(box, client):
    r = client.post("/diffuser", headers=box.porteur(box.jeton("gk2")))
    assert r.status_code == 200


# ── Qui ne passe pas ──────────────────────────────────────────────────────
def test_appareil_guest_refuse(box, client):
    r = _post(box, client, box.jeton(GUEST))
    assert r.status_code == 403
    assert "personnes" in r.json()["detail"]


def test_appareil_guest_refuse_aussi_en_lecture(box, client):
    r = client.get("/diffuser", headers=box.cookie(box.jeton(GUEST)))
    assert r.status_code == 403


def test_appareil_guest_garde_sa_session(box, client):
    # Le plancher ne retire rien à require_session : le Hall lui reste ouvert.
    assert client.get("/lire", headers=box.cookie(box.jeton(GUEST))).status_code == 200


def test_compte_de_role_guest_refuse(box, client):
    assert _post(box, client, box.jeton("visiteur")).status_code == 403


def test_appareil_revoque_ou_compte_desactive_non_reconnus(box, client):
    for sub in (REVOQUE, "ancien", "inconnu", "sbx-ffffffffffff"):
        assert _post(box, client, box.jeton(sub)).status_code == 401, sub


@pytest.mark.parametrize("sub", ["alice", USER, ADMIN, "gk2"])
def test_session_plafonnee_guest_refusee(box, client, sub):
    # Lien d'entrée à usage unique : plafonné à guest, quel que soit le profil.
    r = _post(box, client, box.jeton(sub, plafond="guest"))
    assert r.status_code == 403


def test_plafond_inconnu_refuse(box, client):
    assert _post(box, client, box.jeton(USER, plafond="super")).status_code == 403


def test_plafond_user_n_empeche_pas_une_personne(box, client):
    assert _post(box, client, box.jeton(USER, plafond="user")).status_code == 200


def test_jeton_a_portee_restreinte_refuse(box, client):
    # jti vivant : c'est la portée seule qui ferme.
    assert _post(box, client, box.jeton("gk2", scope="mfa-challenge")).status_code == 401
    assert not auth.est_personne({"sub": "gk2", "jti": "x", "scope": "set-password"})


def test_sans_session_refuse(box, client):
    assert client.post("/diffuser").status_code == 401


# ── Le plancher passe par la garde d'origine ─────────────────────────────
def test_personne_par_cookie_origine_etrangere_refusee_en_applique(box, client, monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "applique")
    r = client.post("/diffuser", headers=box.cookie(box.jeton("alice"), Origin="https://ailleurs.example.net"))
    assert r.status_code == 403
    assert r.json()["detail"] == "Origine refusée"


def test_personne_par_porteur_exemptee_de_la_garde(box, client, monkeypatch):
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE", "applique")
    r = client.post("/diffuser", headers=box.porteur(box.jeton("alice"), Origin="https://ailleurs.example.net"))
    assert r.status_code == 200


# ── Le plafond borne aussi l'administration ──────────────────────────────
def test_plafond_sous_admin_ferme_l_administration(box, client):
    assert client.post("/administrer", headers=box.cookie(box.jeton("gk2"))).status_code == 200
    for plafond in ("guest", "user", "autre"):
        tok = box.jeton("gk2", plafond=plafond)
        assert client.post("/administrer", headers=box.cookie(tok)).status_code == 403, plafond
    assert client.post("/administrer", headers=box.cookie(box.jeton("gk2", plafond="admin"))).status_code == 200


def test_predicat_sans_registre_lisible(box, monkeypatch):
    def casse(_):
        raise OSError("illisible")
    monkeypatch.setattr(auth.user_store, "get_user", casse)
    assert not auth.est_personne({"sub": "alice", "jti": "x"})
