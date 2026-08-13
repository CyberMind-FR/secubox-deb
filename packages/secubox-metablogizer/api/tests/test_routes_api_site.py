# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metablogizer — routes d'API exposées par un site (#1032)

CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from main import bloc_routes_api, routes_api_du_site


def test_absent_par_defaut():
    """UN SITE N'EXPOSE RIEN TANT QUE PERSONNE NE L'A ECRIT."""
    assert routes_api_du_site({}) == []
    assert routes_api_du_site({"api": None}) == []
    assert bloc_routes_api([]) == ""


def test_une_route_conforme_passe():
    assert routes_api_du_site({"api": ["/api/v1/torrent/recherche"]}) == [
        "/api/v1/torrent/recherche"]


def test_les_doublons_ne_produisent_qu_un_bloc():
    """Deux `location =` identiques font REFUSER toute la configuration nginx :
    le site entier tomberait pour une ligne recopiee deux fois."""
    r = routes_api_du_site({"api": ["/api/v1/torrent/recherche"] * 2})
    assert r == ["/api/v1/torrent/recherche"]


def test_l_injection_nginx_est_refusee():
    """LE MOTIF EST LA GARDE. Un point-virgule ferme la directive et ce qui suit
    devient de la configuration : c'est une prise de controle du vhost, pas une
    coquille."""
    for hostile in [
        "/api/v1/x/y; }\nserver { listen 80; server_name mal.example.com;",
        "/api/v1/x/y ; return 200 'pwned'",
        "/api/v1/x/y#",
        "/api/v1/x/y$uri",
        "/api/v1/x/y*",
    ]:
        assert routes_api_du_site({"api": [hostile]}) == [], hostile


def test_la_traversee_est_refusee():
    assert routes_api_du_site({"api": ["/api/v1/x/../../etc/passwd"]}) == []


def test_hors_du_prefixe_api_refuse():
    """Seul `/api/v1/<module>/…` est exposable : proxyfier `/` renverrait le
    site entier vers l'agregateur."""
    for r in ["/", "/etc/passwd", "/api/v2/x/y", "api/v1/x/y", "/api/v1//y"]:
        assert routes_api_du_site({"api": [r]}) == [], r


def test_les_non_chaines_sont_ignorees_sans_emporter_les_autres():
    """Une entree aberrante ne doit pas priver le site des routes valides."""
    r = routes_api_du_site({"api": [None, 42, {}, "/api/v1/torrent/recherche"]})
    assert r == ["/api/v1/torrent/recherche"]


def test_le_bloc_emis_est_en_correspondance_exacte():
    """`location =` et non `location /` : un prefixe exposerait tout le module,
    y compris les routes qu'on y ajoutera sans repenser a ce vhost."""
    b = bloc_routes_api(["/api/v1/torrent/recherche"])
    assert "location = /api/v1/torrent/recherche {" in b
    assert "location /api/v1/torrent/ {" not in b
    assert "unix:/run/secubox/aggregator.sock:/api/v1/torrent/recherche" in b
