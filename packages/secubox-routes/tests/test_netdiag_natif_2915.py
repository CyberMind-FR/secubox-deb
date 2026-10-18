# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2915 — netdiag porte Routes et Reseau en direct en CODE NATIF (plus d'iframes).

Le test charge la vraie page dans jsdom, avec des API simulees, et verifie ce qu'elle rend et ce qu'elle appelle."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
PAGE = ICI / "composants/netdiag/www/netdiag/index.html"
HARNAIS = ICI / "tests" / "jsdom_netdiag.js"


@pytest.fixture(scope="module")
def constats():
    if not shutil.which("node"):
        pytest.skip("node absent")
    r = subprocess.run(["node", str(HARNAIS), str(PAGE)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    if out.get("absent"):
        pytest.skip("jsdom absent")
    return out


def test_plus_aucune_iframe(constats):
    assert constats["iframes"] == 0
    assert not constats["ancienOngletSoc"] and not constats["ancienOngletGestion"]


def test_routes_gerees_dans_la_page(constats):
    assert constats["formRoute"]
    assert constats["supprimerIPv4"] == 2
    assert constats["reglesLignes"] == 2 and constats["tablesLignes"] == 1


def test_suppression_avec_confirmation_integree(constats):
    assert constats["deleteAvantAveu"] is False and constats["aveuAffiche"] is True
    assert len(constats["deleteApresAveu"]) == 1
    assert json.loads(constats["deleteApresAveu"][0])["destination"] == "default"


def test_ajout_de_route_envoie_le_bon_corps(constats):
    assert len(constats["post"]) == 1
    assert json.loads(constats["post"][0]) == {"destination": "198.51.100.0/24", "gateway": "192.0.2.254"}


def test_onglet_temps_reel_rend_les_mesures(constats):
    assert "Entrant maintenant" in constats["tuilesDirect"]
    assert constats["cartesDirect"] == 1 and constats["dropsDirect"] == 1
