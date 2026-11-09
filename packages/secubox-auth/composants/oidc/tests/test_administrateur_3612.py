# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3612 — un administrateur réel entre en son nom dans un service qui l'accepte (opt-in par client, audité)."""
import json
import uuid

import pytest

from secubox_core import auth
from test_oidc import _autorise, cli  # noqa: F401 — fixture partagée
from api import fournisseur as F
from api import main as M


@pytest.fixture
def admin(cli, tmp_path, monkeypatch):  # noqa: F811
    cli.etat["ident"] = None                       # aucune personne derrière la session
    cli.etat["session"] = True
    session = {"payload": {"sub": "admin"}, "admin": True}
    monkeypatch.setattr(auth, "_validate_token", lambda tok: dict(session["payload"]) if tok else None)
    monkeypatch.setattr(auth, "est_admin_reel", lambda p: session["admin"])
    monkeypatch.setattr(M, "AUDIT", tmp_path / "audit.log")
    cli.cookies = {auth.SESSION_COOKIE: "jeton"}
    cli.session = session
    return cli


def _accepte(admins):
    d = json.loads(F.CLIENTS.read_text())
    d["photos"]["administrateurs"] = admins
    F.CLIENTS.write_text(json.dumps(d))


def _get(cli, **extra):
    p = {"response_type": "code", "client_id": "photos", "redirect_uri": "https://photos.exemple/api/v1/oidc/redirect",
         "scope": "openid email profile", "state": "S", "nonce": "N", **extra}
    return cli.get("/authorize", params=p, cookies=cli.cookies)


def test_sans_opt_in_l_administrateur_reste_refuse(admin):
    r = _get(admin)
    assert r.status_code == 403 and "aucune personne" in r.text.lower()


def test_avec_opt_in_l_administrateur_entre_et_c_est_audite(admin, tmp_path):
    _accepte(True)
    r = _get(admin)
    assert r.status_code == 302 and "code=" in r.headers["location"]
    ligne = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert ligne["evenement"] == "oidc_entree_administrateur" and ligne["compte"] == "admin" and ligne["client"] == "photos"


def test_opt_in_strictement_vrai(admin):
    _accepte("true")
    assert _get(admin).status_code == 403


@pytest.mark.parametrize("payload,est_admin", [
    ({"sub": "admin"}, False),                                   # compte non administrateur
    ({"sub": "sbx-appareil"}, True),                            # appareil
    ({"sub": "pilotage:gk2"}, True),                            # porteur délégué du pilotage
    ({"sub": "admin", "plafond": "user"}, True),                # session plafonnée
    ({"sub": "Admin Espace"}, True),                            # nom de compte hors motif
])
def test_jamais_hors_session_d_administrateur_reel(admin, payload, est_admin):
    _accepte(True)
    admin.session["payload"], admin.session["admin"] = payload, est_admin
    assert _get(admin).status_code == 403


def test_identite_stable_et_distincte_des_personnes(admin, monkeypatch):
    _accepte(True)
    vus = []
    monkeypatch.setattr(M, "claims_pour", lambda ident, c: vus.append(ident["per"]) or {"sub": ident["per"]["user_uuid"]})
    _get(admin)
    _get(admin)
    assert vus[0] == vus[1] and vus[0]["pseudo"] == "admin"
    assert uuid.UUID(vus[0]["user_uuid"]).version == 5
