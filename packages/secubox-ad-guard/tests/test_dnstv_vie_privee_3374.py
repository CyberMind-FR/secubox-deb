# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SBX TV PRIVACY (#3374) : aucune donnée personnelle par appareil (MAC, IP, domaines visités) n'est servie au lecteur
anonyme du mode tableau de bord. Constat gk2 : le « LAN » nginx inclut le réseau de la box opérateur."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from test_dnstv_ctl_api import ctl, monde  # noqa: F401  (fixtures)

PERSONNELLES = [
    "/adblock-tv/appareils", "/adblock-tv/classification", "/adblock-tv/stats", "/adblock-tv/export", "/adblock-tv/clients/vus",
    "/adblock-tv/path-test?ip=192.168.1.50", "/adblock-tv/bypass", "/adblock-tv/sources", "/adblock-tv/live", "/adblock-tv/flux",
    "/adblock-tv/serie", "/adblock-tv/auto/regles", "/adblock-tv/auto/reglage", "/adblock-tv/auto/detection",
    "/adblock-tv/auto/appareils/TV/refus", "/adblock-tv/simple", "/adblock-tv/simple/suspects",
]


def _client(monde, lecteur):
    from secubox_core import auth
    from api import dnstv_routes as r
    app = FastAPI()
    app.include_router(r.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: lecteur
    return TestClient(app)


@pytest.mark.parametrize("chemin", PERSONNELLES)
def test_le_tableau_de_bord_anonyme_est_refuse(monde, chemin):
    r = _client(monde, {"sub": None, "tableau_de_bord": True}).get(chemin)
    assert r.status_code in (401, 403), (chemin, r.status_code)


@pytest.mark.parametrize("chemin", ["/adblock-tv/appareils", "/adblock-tv/classification", "/adblock-tv/stats", "/adblock-tv/live",
                                    "/adblock-tv/clients/vus", "/adblock-tv/simple"])
def test_une_session_est_servie(monde, chemin):
    assert _client(monde, {"sub": "admin"}).get(chemin).status_code == 200


def test_le_statut_reste_servi_au_tableau_de_bord_sans_appareils(monde):
    api = _client(monde, {"sub": None, "tableau_de_bord": True})
    r = api.get("/adblock-tv/status")
    assert r.status_code == 200
    j = r.json()
    assert j["clients"] == [] and j["appareils"] == [] and "compteurs" in j and "listes" in j


@pytest.mark.parametrize("chemin", ["/adblock-tv/limites", "/adblock-tv/custom", "/adblock-tv/auto/profil"])
def test_les_routes_agregees_restent_au_tableau_de_bord(monde, chemin):
    assert _client(monde, {"sub": None, "tableau_de_bord": True}).get(chemin).status_code == 200


def test_toutes_les_routes_personnelles_portent_la_garde_nominative():
    from api import dnstv_routes as r
    gardes = {x.path: {d.call for d in x.dependant.dependencies} for x in r.router.routes if "GET" in getattr(x, "methods", ())}
    for chemin in PERSONNELLES:
        p = chemin.split("?")[0].replace("/TV/", "/{nom}/")
        assert r.require_lecture_nominative in gardes[p], p
