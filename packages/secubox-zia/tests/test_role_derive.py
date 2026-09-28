# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Le rôle ZIA se DÉRIVE de la session (#1411) ; le corps ne peut que restreindre.

« admin » = l'administrateur réel seulement (#1581) : un compte utilisateur actif
de rôle admin. Un appareil admis n'est jamais admin, quel que soit son profil.

On vérifie séparément la LOGIQUE (dérivation du rôle), la GARDE (exige_admin) et
l'EFFET sur les routes (client ASGI sur l'application réelle).
"""
import asyncio
import os
import time
from pathlib import Path

import pytest

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[3] / "secubox.conf.example"]

main = pytest.importorskip("api.main")
import httpx  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from starlette.requests import Request  # noqa: E402
from secubox_core import auth, user_store, appareils  # noqa: E402

_ORDRE = ["guest", "registered", "member", "admin"]

# Comptes utilisateurs jetables. « ancien » : administrateur désactivé.
# « sbx-x » : un nom d'appareil qui apparaîtrait aussi côté comptes.
_COMPTES = {
    "gk2": {"role": "admin", "enabled": True},
    "op": {"role": "operator", "enabled": True},
    "lectrice": {"role": "user", "enabled": True},
    "ancien": {"role": "admin", "enabled": False},
    "sbx-x": {"role": "admin", "enabled": True},
}
# Appareils admis, par profil.
_PROFILS = {"sbx-a": "admin", "sbx-u": "user", "sbx-x": "admin"}


def _req(jeton=None, cookie=None):
    h = []
    if jeton:
        h.append((b"authorization", f"Bearer {jeton}".encode()))
    if cookie:
        h.append((b"cookie", f"{auth.SESSION_COOKIE}={cookie}".encode()))
    return Request({"type": "http", "method": "POST", "path": "/", "headers": h})


@pytest.fixture
def porteurs(monkeypatch):
    # Un jeton « vaut » son sujet ; « faux » ne se valide pas.
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": t} if t != "faux" else None)
    monkeypatch.setattr(user_store, "get_user", lambda s: _COMPTES.get(s))
    monkeypatch.setattr(user_store, "is_enabled",
                        lambda s: bool((_COMPTES.get(s) or {}).get("enabled", False)))
    monkeypatch.setattr(appareils, "profil_de", lambda s: _PROFILS.get(s, "guest"))


# ── LOGIQUE : dérivation du rôle ────────────────────────────────────────────

@pytest.mark.parametrize("jeton,attendu", [
    (None, "guest"), ("faux", "guest"),
    ("gk2", "admin"), ("op", "member"), ("lectrice", "member"),
    ("sbx-a", "member"), ("sbx-u", "member"), ("sbx-g", "registered"),
])
def test_role_derive_de_la_session(porteurs, jeton, attendu):
    assert main._role_du_porteur(_req(jeton)) == attendu


def test_appareil_profil_admin_plafonne_a_membre(porteurs):
    assert main._role_du_porteur(_req("sbx-a")) == "member"
    assert main._role_du_porteur(_req(cookie="sbx-a")) == "member"


def test_nom_d_appareil_jamais_admin_meme_present_cote_comptes(porteurs):
    assert main._role_du_porteur(_req("sbx-x")) != "admin"


def test_compte_admin_desactive_n_est_pas_admin(porteurs):
    assert main._role_du_porteur(_req("ancien")) != "admin"


def test_compte_admin_reel_est_admin_par_cookie(porteurs):
    assert main._role_du_porteur(_req(cookie="gk2")) == "admin"


def test_bearer_invalide_ne_masque_pas_la_session_du_cookie(porteurs):
    assert main._role_du_porteur(_req("faux", cookie="gk2")) == "admin"


def test_schema_bearer_insensible_a_la_casse(porteurs):
    r = Request({"type": "http", "method": "POST", "path": "/",
                 "headers": [(b"authorization", b"bearer gk2")]})
    assert main._role_du_porteur(r) == "admin"


# ── LOGIQUE : le corps ne peut que restreindre ──────────────────────────────

def test_le_corps_ne_peut_que_restreindre(porteurs):
    assert main._role_effectif(_req(None), "admin") == "guest"
    assert main._role_effectif(_req("sbx-g"), "admin") == "registered"
    assert main._role_effectif(_req("gk2"), "guest") == "guest"     # se restreindre : permis
    assert main._role_effectif(_req("gk2"), "n'importe") == "admin"


def test_demande_admin_par_un_membre_ignoree(porteurs):
    assert main._role_effectif(_req("op"), "admin") == "member"
    assert main._role_effectif(_req("sbx-a"), "admin") == "member"
    assert main._role_effectif(_req("sbx-a"), " ADMIN ") == "member"


@pytest.mark.parametrize("jeton", [None, "faux", "gk2", "op", "ancien", "sbx-a", "sbx-u",
                                   "sbx-g", "sbx-x"])
@pytest.mark.parametrize("demande", [None, "", "guest", "registered", "member", "admin",
                                     "ADMIN", " admin ", "root", "superadmin", "admin|member"])
def test_la_demande_n_eleve_jamais(porteurs, jeton, demande):
    reel = main._role_du_porteur(_req(jeton))
    eff = main._role_effectif(_req(jeton), demande)
    assert _ORDRE.index(eff) <= _ORDRE.index(reel)


# ── GARDE : exige_admin ─────────────────────────────────────────────────────

@pytest.mark.parametrize("jeton", ["op", "lectrice", "ancien", "sbx-a", "sbx-u", "sbx-x"])
def test_administration_refusee_hors_admin_reel(porteurs, jeton):
    with pytest.raises(HTTPException) as e:
        asyncio.run(main.exige_admin(_req(jeton)))
    assert e.value.status_code == 403


def test_administration_sans_session_401(porteurs):
    for r in (_req(None), _req("faux")):
        with pytest.raises(HTTPException) as e:
            asyncio.run(main.exige_admin(r))
        assert e.value.status_code == 401


def test_administration_permise_a_l_admin_reel(porteurs):
    p = asyncio.run(main.exige_admin(_req("gk2")))
    assert p["sub"] == "gk2"
    p = asyncio.run(main.exige_admin(_req(cookie="gk2")))
    assert p["sub"] == "gk2"


# ── EFFET : les routes de l'application ─────────────────────────────────────

class _Client:
    """Client ASGI minimal (httpx.ASGITransport) : ne dépend pas de la version
    de starlette.testclient, et ne pose aucun en-tête implicite."""

    def __init__(self, app):
        self.app = app
        self.cookies = {}

    def request(self, method, url, headers=None, json=None):
        async def _go():
            tr = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=tr, base_url="http://zia",
                                         cookies=self.cookies) as c:
                return await c.request(method, url, headers=headers, json=json)
        return asyncio.run(_go())

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


@pytest.fixture
def client(porteurs, monkeypatch):
    # Aucune écriture hors du bac à sable : la surcouche de config est détournée.
    ecrits = []
    monkeypatch.setattr(main, "_save_overlay", lambda cfg: ecrits.append(dict(cfg)))

    async def _repond(message, role, tools, cfg, remote=None):
        return {"text": "ok", "objects": [], "trace": [], "delegate": None,
                "engine": "heuristique"}
    monkeypatch.setattr(main.runtime, "respond", _repond)
    c = _Client(main.app)
    c.ecrits = ecrits
    return c


def _bearer(jeton):
    return {"Authorization": f"Bearer {jeton}"}


@pytest.mark.parametrize("jeton", ["sbx-a", "sbx-u", "op", "ancien"])
def test_config_refusee_hors_admin_reel(client, jeton):
    avant = dict(main.CFG)
    assert client.get("/config", headers=_bearer(jeton)).status_code == 403
    r = client.post("/config", headers=_bearer(jeton), json={"llm_url": "http://ailleurs"})
    assert r.status_code == 403
    assert client.post("/llm/test", headers=_bearer(jeton)).status_code == 403
    assert main.CFG == avant and client.ecrits == []


def test_config_refusee_a_l_appareil_par_cookie(client):
    client.cookies[auth.SESSION_COOKIE] = "sbx-a"
    assert client.get("/config").status_code == 403


def test_config_sans_session_401(client):
    assert client.get("/config").status_code == 401
    assert client.post("/llm/test").status_code == 401


def test_config_lue_par_l_admin_reel(client):
    r = client.get("/config", headers=_bearer("gk2"))
    assert r.status_code == 200
    assert set(r.json()) == set(main.DEFAULT_CONFIG)


@pytest.mark.parametrize("jeton,attendu", [
    (None, "guest"), ("sbx-a", "member"), ("sbx-u", "member"), ("sbx-g", "registered"),
    ("op", "member"), ("ancien", "member"), ("gk2", "admin"),
])
def test_chat_meta_role(client, jeton, attendu):
    h = _bearer(jeton) if jeton else {}
    r = client.post("/v1/chat", headers=h, json={"message": "bonjour", "role": "admin"})
    assert r.status_code == 200
    assert r.json()["meta"]["role"] == attendu


def test_chat_role_transmis_au_moteur(client, monkeypatch):
    vus = []

    async def _repond(message, role, tools, cfg, remote=None):
        vus.append(role)
        return {"text": "ok", "objects": [], "trace": [], "delegate": None,
                "engine": "heuristique"}
    monkeypatch.setattr(main.runtime, "respond", _repond)
    client.post("/v1/chat", headers=_bearer("sbx-a"), json={"message": "x", "role": "admin"})
    assert vus == ["member"]


def test_metrics_compte_selon_le_role_du_demandeur(client, monkeypatch):
    objets = [{"id": f"o{v}", "visibility": v} for v in _ORDRE]
    monkeypatch.setattr(main.BUS, "_cache", objets)
    monkeypatch.setattr(main.BUS, "_ts", time.time())
    monkeypatch.setattr(main.BUS, "ttl", 3600.0)
    assert client.get("/metrics", headers=_bearer("sbx-a")).json()["objets_bus"] == 3
    assert client.get("/metrics", headers=_bearer("gk2")).json()["objets_bus"] == 4
