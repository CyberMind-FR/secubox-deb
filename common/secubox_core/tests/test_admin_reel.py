# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""L'administration est réservée aux ADMINISTRATEURS RÉELS (#1581).

Une session d'invité (l'appareil de gek) ouvrait la webui d'administration et
ses API : `require_jwt` n'exigeait qu'un porteur reconnu. Désormais :
`require_session` = n'importe quelle session ; `require_jwt` = session + compte
utilisateur de rôle admin, jamais un appareil."""
import asyncio

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from secubox_core import auth


class _Req:
    cookies = {}


def _cred():
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials="jeton")


@pytest.fixture
def porteur(monkeypatch):
    """Simule un jeton valide dont on choisit le porteur, et le registre."""
    etat = {"sub": None, "users": {}}
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": etat["sub"], "jti": "j"})
    monkeypatch.setattr(auth.user_store, "get_user", lambda s: etat["users"].get(s))
    monkeypatch.setattr(auth.user_store, "is_enabled",
                        lambda s: bool((etat["users"].get(s) or {}).get("enabled")))
    return etat


def _jwt():
    return asyncio.run(auth.require_jwt(_Req(), _cred()))


def _session():
    return asyncio.run(auth.require_session(_Req(), _cred()))


def test_appareil_invite_refuse_a_l_administration(porteur):
    porteur["sub"] = "sbx-47320289526c"            # gek, profil guest
    assert _session()["sub"] == "sbx-47320289526c"  # le Hall lui reste ouvert
    with pytest.raises(HTTPException) as e:
        _jwt()
    assert e.value.status_code == 403


def test_appareil_profil_admin_refuse_aussi(porteur):
    # Un appareil entre en signant : pas une preuve pour administrer.
    porteur["sub"] = "sbx-aafc7d62d710"
    porteur["users"]["sbx-aafc7d62d710"] = {"role": "admin", "enabled": True}
    with pytest.raises(HTTPException):
        _jwt()


def test_utilisateur_non_admin_refuse(porteur):
    porteur["sub"] = "operator"
    porteur["users"]["operator"] = {"role": "operator", "enabled": True}
    with pytest.raises(HTTPException) as e:
        _jwt()
    assert e.value.status_code == 403


def test_admin_desactive_refuse(porteur):
    porteur["sub"] = "gk2"
    porteur["users"]["gk2"] = {"role": "admin", "enabled": False}
    with pytest.raises(HTTPException):
        _jwt()


def test_admin_reel_passe(porteur):
    porteur["sub"] = "gk2"
    porteur["users"]["gk2"] = {"role": "admin", "enabled": True}
    assert _jwt()["sub"] == "gk2"


def test_role_absent_n_est_pas_admin():
    # user_store rendait « admin » à un compte sans rôle.
    import inspect
    from secubox_core import user_store
    assert 'entry.get("role", "admin")' not in inspect.getsource(user_store)
