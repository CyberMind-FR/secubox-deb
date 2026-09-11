# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: lecture gardée + mode tableau de bord (#1256).

Le parc passe de « lecture publique, écriture gardée » à « lecture gardée,
avec un mode tableau de bord explicite ». `require_lecture` porte cette
politique ; ces tests fixent son contrat, et surtout ses **échecs**.

Trois propriétés comptent plus que le chemin nominal :

1. **le défaut est fermé** — mode absent de la config ⇒ 401 même depuis le LAN ;
2. **l'en-tête LAN n'ouvre rien à lui seul** — sans le mode armé, il est inerte ;
3. **il n'est pas forgeable** — nginx le pose avec `proxy_set_header`, qui
   écrase la valeur du client ; une requête qui ne passe pas par nginx ne le
   porte pas du tout et retombe sur l'exigence du jeton.

La troisième ne se teste pas en Python (c'est nginx qui l'assure) mais la
conséquence, elle, se teste : sans en-tête, c'est 401.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from secubox_core import auth


class _FausseRequete:
    """Le strict nécessaire : des en-têtes et des cookies."""

    def __init__(self, headers=None, cookies=None):
        self.headers = headers or {}
        self.cookies = cookies or {}


@pytest.fixture(autouse=True)
def _mode_ferme(monkeypatch):
    """Chaque test part du défaut : mode inactif."""
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")


async def _appel(requete):
    return await auth.require_lecture(requete, creds=None)


# ── Le défaut ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_defaut_ferme_meme_depuis_le_lan():
    """Sans mode armé, une requête LAN sans jeton est refusée.

    C'est LA propriété qui distingue ce mode d'un contournement : il ne
    s'active pas tout seul, et surtout pas parce que l'appelant est « chez
    lui ». Même doctrine que `waf_bypass` — jamais un défaut silencieux.
    """
    with pytest.raises(HTTPException) as e:
        await _appel(_FausseRequete({auth.ENTETE_LAN: "1"}))
    assert e.value.status_code == 401


@pytest.mark.asyncio
async def test_mode_arme_mais_requete_non_lan_refusee(monkeypatch):
    """Mode armé ne veut pas dire ouvert : hors LAN, il ne s'applique pas."""
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    for entetes in ({}, {auth.ENTETE_LAN: "0"}, {auth.ENTETE_LAN: ""}):
        with pytest.raises(HTTPException) as e:
            await _appel(_FausseRequete(entetes))
        assert e.value.status_code == 401, entetes


@pytest.mark.asyncio
async def test_mode_arme_et_lan_autorise_en_lecteur_anonyme(monkeypatch):
    """Le seul chemin qui ouvre — et il se déclare comme tel.

    Le pseudo-payload porte `sub = None` : une route peut ainsi taire ce qui
    ne regarde pas un lecteur anonyme, au lieu de croire qu'un utilisateur
    est identifié.
    """
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    payload = await _appel(_FausseRequete({auth.ENTETE_LAN: "1"}))
    assert payload["tableau_de_bord"] is True
    assert payload["sub"] is None


# ── L'en-tête absent : le cas d'un service non passé par nginx ─────────
@pytest.mark.asyncio
async def test_absence_d_entete_ferme(monkeypatch):
    """Une requête qui n'est pas passée par nginx n'a pas l'en-tête.

    Elle doit alors être traitée comme non-LAN : c'est ce qui évite qu'un
    appel direct sur la socket Unix hérite du mode tableau de bord.
    """
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    with pytest.raises(HTTPException) as e:
        await _appel(_FausseRequete({}))
    assert e.value.status_code == 401


# ── Le jeton prime toujours ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_le_jeton_valide_prime_sur_le_mode(monkeypatch):
    """Avec un jeton valide, on rend l'identité — pas le pseudo-payload.

    Le mode tableau de bord est un plancher, pas un plafond : il ne doit
    jamais dégrader une requête authentifiée en lecteur anonyme.
    """
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": "admin", "jti": "x"})
    req = _FausseRequete({}, {auth.SESSION_COOKIE: "peu-importe"})
    payload = await _appel(req)
    assert payload["sub"] == "admin"
    assert "tableau_de_bord" not in payload


@pytest.mark.asyncio
async def test_jeton_invalide_et_mode_arme_depuis_le_lan_passe(monkeypatch):
    """Un cookie périmé ne doit pas condamner un lecteur LAN légitime.

    Symétrique du correctif de `require_jwt` (#400) : un jeton mort qui
    traîne dans localStorage ne doit jamais faire échouer une requête qu'un
    autre chemin autorise.
    """
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    monkeypatch.setattr(auth, "_validate_token", lambda t: None)
    req = _FausseRequete({auth.ENTETE_LAN: "1"}, {auth.SESSION_COOKIE: "perime"})
    payload = await _appel(req)
    assert payload["tableau_de_bord"] is True


# ── La lecture du mode dans la config ──────────────────────────────────
def test_config_illisible_vaut_ferme(monkeypatch):
    """Une config cassée ne doit pas ouvrir la lecture."""
    monkeypatch.delenv("SECUBOX_TABLEAU_DE_BORD", raising=False)
    monkeypatch.setattr(auth, "get_config", lambda s: (_ for _ in ()).throw(OSError("boom")))
    assert auth.mode_tableau_de_bord_actif() is False


def test_config_absente_vaut_ferme(monkeypatch):
    monkeypatch.delenv("SECUBOX_TABLEAU_DE_BORD", raising=False)
    monkeypatch.setattr(auth, "get_config", lambda s: {})
    assert auth.mode_tableau_de_bord_actif() is False


def test_config_explicite_arme_le_mode(monkeypatch):
    monkeypatch.delenv("SECUBOX_TABLEAU_DE_BORD", raising=False)
    monkeypatch.setattr(auth, "get_config", lambda s: {"actif": True})
    assert auth.mode_tableau_de_bord_actif() is True


def test_valeur_non_booleenne_ne_arme_pas(monkeypatch):
    """« true » en chaîne, 1, "oui"… ne valent pas `true` TOML.

    On exige le booléen : un `actif = "true"` mal typé dans le TOML ne doit
    pas ouvrir la lecture du parc par accident.
    """
    monkeypatch.delenv("SECUBOX_TABLEAU_DE_BORD", raising=False)
    for valeur in ("true", 1, "oui", "1"):
        monkeypatch.setattr(auth, "get_config", lambda s, v=valeur: {"actif": v})
        assert auth.mode_tableau_de_bord_actif() is False, valeur
