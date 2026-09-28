# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Fournisseur OIDC SecuBox (#1589) : le flux complet et ses refus."""
import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import asyncio

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import fournisseur as F  # noqa: E402
from api import main as M  # noqa: E402

class _Client:
    """Client ASGI synchrone — sans TestClient, dont la version de Starlette
    ne s'accorde pas partout avec httpx."""

    def _appel(self, meth, url, **kw):
        async def go():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=M.app),
                                         base_url="http://oidc.test") as c:
                return await c.request(meth, url, **kw)
        return asyncio.run(go())

    def get(self, url, follow_redirects=False, **kw):
        return self._appel("GET", url, follow_redirects=follow_redirects, **kw)

    def post(self, url, **kw):
        return self._appel("POST", url, **kw)


REDIR = "https://photos.exemple/api/v1/oidc/redirect"
SECRET = "le-secret-du-client"
PERSONNE = {"sub": "fd980586-ccb5-43de-9af6-faeae690bb42", "preferred_username": "gek",
            "name": "gek", "nickname": "gek", "email": "gek@exemple", "email_verified": False}


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "CLE", tmp_path / "cle.pem")
    monkeypatch.setattr(F, "CLIENTS", tmp_path / "clients.json")
    monkeypatch.setattr(F, "BASE", tmp_path / "oidc.db")
    monkeypatch.setattr(M, "CONF", tmp_path / "oidc.toml")
    (tmp_path / "oidc.toml").write_text('issuer = "https://hall.exemple/oidc"\n')
    F.cree_cle()
    (tmp_path / "clients.json").write_text(json.dumps({"photos": {
        "name": "Photos", "app": "photoprism", "redirect_uris": [REDIR],
        "secret_sha256": F.empreinte(SECRET)}}))
    etat = {"ident": {"payload": {"sub": "sbx-1"}, "per": {"user_uuid": PERSONNE["sub"], "pseudo": "gek"}}}
    monkeypatch.setattr(M, "personne", lambda req: etat["ident"])
    monkeypatch.setattr(M, "claims_pour", lambda ident, c: dict(PERSONNE))
    c = _Client()
    c.etat = etat
    return c


def _autorise(cli, **extra):
    p = {"response_type": "code", "client_id": "photos", "redirect_uri": REDIR,
         "scope": "openid email profile address", "state": "S", "nonce": "N", **extra}
    return cli.get("/authorize", params=p, follow_redirects=False)


def _code(r):
    q = parse_qs(urlsplit(r.headers["location"]).query)
    return q.get("code", [""])[0], q


def _echange(cli, code, **extra):
    d = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIR, **extra}
    return cli.post("/token", data=d, auth=("photos", SECRET))


def test_decouverte_et_jwks(cli):
    d = cli.get("/.well-known/openid-configuration").json()
    assert d["issuer"] == "https://hall.exemple/oidc"
    assert d["token_endpoint"] == "https://hall.exemple/oidc/token"
    k = cli.get("/jwks").json()["keys"][0]
    assert k["alg"] == "RS256" and "d" not in k       # jamais la partie privée


def test_flux_complet(cli):
    r = _autorise(cli)
    assert r.status_code == 302
    code, q = _code(r)
    assert code and q["state"] == ["S"]
    t = _echange(cli, code)
    assert t.status_code == 200 and t.headers["cache-control"] == "no-store"
    j = t.json()
    cle = jwt.PyJWK(cli.get("/jwks").json()["keys"][0]).key
    idt = jwt.decode(j["id_token"], cle, algorithms=["RS256"], audience="photos",
                     issuer="https://hall.exemple/oidc")
    assert idt["sub"] == PERSONNE["sub"] and idt["nonce"] == "N"
    assert idt["preferred_username"] == "gek"
    u = cli.get("/userinfo", headers={"Authorization": "Bearer " + j["access_token"]}).json()
    assert u["preferred_username"] == "gek" and "auth_time" not in u


def test_code_a_usage_unique(cli):
    code, _ = _code(_autorise(cli))
    assert _echange(cli, code).status_code == 200
    r = _echange(cli, code)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_mauvais_secret_et_mauvaise_redirection(cli):
    code, _ = _code(_autorise(cli))
    r = cli.post("/token", data={"grant_type": "authorization_code", "code": code,
                                 "redirect_uri": REDIR}, auth=("photos", "faux"))
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    # redirect_uri différente au moment de l'échange : refus
    code, _ = _code(_autorise(cli))
    r = cli.post("/token", data={"grant_type": "authorization_code", "code": code,
                                 "redirect_uri": REDIR + "x"}, auth=("photos", SECRET))
    assert r.json()["error"] == "invalid_grant"


def test_pas_de_redirecteur_ouvert(cli):
    r = _autorise(cli, redirect_uri="https://ailleurs.exemple/vol")
    assert r.status_code == 400 and "location" not in r.headers
    r = cli.get("/authorize", params={"client_id": "inconnu", "redirect_uri": REDIR,
                                      "response_type": "code", "scope": "openid"}, follow_redirects=False)
    assert r.status_code == 400 and "location" not in r.headers


def test_sans_session_pas_de_code(cli):
    cli.etat["ident"] = None
    r = _autorise(cli)
    assert r.status_code == 200 and "location" not in r.headers
    r = _autorise(cli, prompt="none")
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["login_required"]


def test_pkce(cli):
    verif = "v" * 50
    defi = base64.urlsafe_b64encode(hashlib.sha256(verif.encode()).digest()).rstrip(b"=").decode()
    code, _ = _code(_autorise(cli, code_challenge=defi, code_challenge_method="S256"))
    assert _echange(cli, code, code_verifier="mauvais" * 8).json()["error"] == "invalid_grant"
    code, _ = _code(_autorise(cli, code_challenge=defi, code_challenge_method="S256"))
    assert _echange(cli, code, code_verifier=verif).status_code == 200
    # « plain » refusé
    r = _autorise(cli, code_challenge="x" * 43, code_challenge_method="plain")
    assert "error" in parse_qs(urlsplit(r.headers["location"]).query)


def test_scope_sans_openid(cli):
    r = _autorise(cli, scope="email")
    assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_scope"]
