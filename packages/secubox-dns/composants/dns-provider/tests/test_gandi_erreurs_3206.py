# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — l'adaptateur Gandi rendait « success » quoi que réponde Gandi (409 doublon, 401 clé refusée, 404 zone) :
le relais du maillage va créer lui-même les jokers DNS des nœuds, il doit savoir quand Gandi refuse. Même schéma
qu'OVH (#3070) : erreur HTTP ou API injoignable → HTTPException 502 avec le message de Gandi."""
import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

COMP = Path(__file__).resolve().parents[1]
RACINE = COMP.parents[3]
sys.path.insert(0, str(RACINE / "common"))


@pytest.fixture
def m(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    spec = importlib.util.spec_from_file_location("dnsprov_3206", COMP / "api" / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(mod, "PROVIDERS_FILE", tmp_path / "providers.json")
    monkeypatch.setattr(mod, "AUDIT_LOG_FILE", tmp_path / "audit.log")
    return mod


def _gandi(m, handler):
    import httpx
    m.GandiAdapter._transport = httpx.MockTransport(handler)
    return m.GandiAdapter({"api_key": "cle-de-test"})


def _joker(m):
    return m.RecordCreate(type=m.RecordType("A"), name="*.gk4", value="82.67.100.75", ttl=300)


def test_creation_acceptee(m):
    import httpx
    vus = []

    def handler(req: httpx.Request) -> httpx.Response:
        vus.append((req.method, req.url.path, req.headers.get("authorization")))
        return httpx.Response(201, json={"message": "DNS Record Created"})

    r = asyncio.run(_gandi(m, handler).create_record("secubox.in", _joker(m)))
    assert r == {"success": True, "id": "*.gk4_A"}
    assert vus == [("POST", "/v5/livedns/domains/secubox.in/records", "Bearer cle-de-test")]


@pytest.mark.parametrize("statut,corps", [
    (409, {"code": 409, "message": "A DNS Record already exists with same value", "object": "HTTPConflict"}),
    (401, {"code": 401, "message": "The server could not verify that you are authorized", "object": "HTTPUnauthorized"}),
    (404, {"code": 404, "message": "The resource could not be found.", "object": "HTTPNotFound"}),
])
def test_un_refus_de_gandi_est_une_erreur(m, statut, corps):
    import httpx
    from fastapi import HTTPException
    g = _gandi(m, lambda req: httpx.Response(statut, json=corps))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(g.create_record("secubox.in", _joker(m)))
    assert exc.value.status_code == 502
    assert f"Gandi API {statut}" in exc.value.detail and corps["message"] in exc.value.detail
    assert "cle-de-test" not in exc.value.detail                                  # jamais la clé dans un message


def test_gandi_injoignable_est_une_erreur(m):
    import httpx
    from fastapi import HTTPException

    def handler(req):
        raise httpx.ConnectError("réseau coupé", request=req)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(_gandi(m, handler).list_records("secubox.in"))
    assert exc.value.status_code == 502 and "injoignable" in exc.value.detail


def test_suppression_sans_contenu_reste_un_succes(m):
    import httpx
    g = _gandi(m, lambda req: httpx.Response(204))
    assert asyncio.run(g._request("DELETE", "/domains/secubox.in/records/*.gk4/A")) == {"success": True}
