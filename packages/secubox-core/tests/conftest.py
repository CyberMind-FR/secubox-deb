# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Une box de poche pour les gardes de secubox_core.auth (#1607).

DE VRAIS JETONS, PAS DES SIMULACRES. Un jeton frappé hors de la box est refusé
si son `jti` ne nomme pas une session vivante : on passe donc par les points
d'injection prévus — le validateur de sessions, les chemins des registres
(users.json, appareils.json) et la configuration en mémoire — et tout le reste
du chemin (`_validate_token`, `porteur_reconnu`, la garde, le plancher) est
celui de la production.
"""
from __future__ import annotations

import json
import logging
import secrets
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from secubox_core import appareils, auth, config, user_store

DOMAINE_COOKIE = ".gk2.secubox.in"
HALL = "https://hall.gk2.secubox.in"

APPAREIL_GUEST = "sbx-00000000000a"
APPAREIL_USER = "sbx-00000000000b"
APPAREIL_ADMIN = "sbx-00000000000c"
APPAREIL_REVOQUE = "sbx-00000000000d"


def _compte(nom, role, actif=True):
    return {
        "username": nom, "email": f"{nom}@example.local", "role": role,
        "enabled": actif, "password_hash": None, "must_change_password": False,
        "totp": None, "google": None, "services": [],
        "created": "2026-09-28T00:00:00+00:00", "last_login": None,
    }


def _appareil(compte, profil, actif=True):
    return {"compte": compte, "nom": compte, "profil": profil, "did": "did:key:" + compte,
            "empreinte": "", "actif": actif, "email": ""}


def par_cookie(tok, **entetes):
    return {"Cookie": f"{auth.SESSION_COOKIE}={tok}", **entetes}


def par_porteur(tok, **entetes):
    return {"Authorization": f"Bearer {tok}", **entetes}


class _Collecte(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lignes = []

    def emit(self, record):
        self.lignes.append(record.getMessage())


@pytest.fixture
def box(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-uniquement-0123456789abcdef")
    monkeypatch.delenv("SECUBOX_GARDE_ORIGINE", raising=False)
    monkeypatch.delenv("SECUBOX_SSO_COOKIE_DOMAIN", raising=False)
    monkeypatch.delenv("SECUBOX_AUTH_PERMISSIVE_SESSIONS", raising=False)
    releve = tmp_path / "garde-origine.log"
    monkeypatch.setenv("SECUBOX_GARDE_ORIGINE_RELEVE", str(releve))

    # La configuration de gk2 : pas de [global] domain, le domaine du cookie.
    monkeypatch.setattr(config, "_CONFIG", {"global": {}, "api": {"sso_cookie_domain": DOMAINE_COOKIE}})

    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("gk2", "admin"),
        _compte("alice", "operator"),
        _compte("visiteur", "guest"),
        _compte("ancien", "operator", actif=False),
    ]}))
    monkeypatch.setattr(user_store, "USERS_PATH", users)
    monkeypatch.setattr(user_store, "AUTH_TOML_PATH", tmp_path / "absent.toml")

    registre = tmp_path / "appareils.json"
    registre.write_text(json.dumps({"appareils": [
        _appareil(APPAREIL_GUEST, "guest"),
        _appareil(APPAREIL_USER, "user"),
        _appareil(APPAREIL_ADMIN, "admin"),
        _appareil(APPAREIL_REVOQUE, "user", actif=False),
    ]}))
    monkeypatch.setattr(appareils, "FICHIER", registre)

    vivantes: set = set()
    monkeypatch.setattr(auth, "_session_validator", lambda jti: jti in vivantes)

    def jeton(sub, **kw):
        jti = secrets.token_hex(8)
        vivantes.add(jti)
        return auth.create_token(sub, jti=jti, **kw)

    collecte = _Collecte()
    journal = logging.getLogger("secubox.origine")
    journal.addHandler(collecte)
    yield SimpleNamespace(jeton=jeton, releve=releve, journal=collecte.lignes,
                          cookie=par_cookie, porteur=par_porteur)
    journal.removeHandler(collecte)


def _application():
    app = FastAPI()

    @app.api_route("/ecrire", methods=["POST", "PUT", "PATCH", "DELETE"])
    async def ecrire(p=Depends(auth.require_session)):
        return {"sub": p["sub"]}

    @app.api_route("/lire", methods=["GET", "HEAD", "OPTIONS"])
    async def lire(p=Depends(auth.require_session)):
        return {"sub": p["sub"]}

    @app.post("/administrer")
    async def administrer(p=Depends(auth.require_jwt)):
        return {"sub": p["sub"]}

    @app.api_route("/diffuser", methods=["GET", "POST"])
    async def diffuser(p=Depends(auth.require_personne)):
        return {"sub": p["sub"]}

    return app


@pytest.fixture
def client_pour():
    """Un client dont on choisit l'hôte de la requête (en-tête Host)."""
    return lambda base: TestClient(_application(), base_url=base)


@pytest.fixture
def client(client_pour):
    return client_pour(HALL)

