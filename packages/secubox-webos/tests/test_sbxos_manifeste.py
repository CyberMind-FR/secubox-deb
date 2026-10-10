# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Manifeste de session SBXOS (#1610) : matrice rôle × LAN, domaine, en-têtes."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import sbxos_manifeste as sm
import api.main as m

SBXOS = Path(__file__).resolve().parents[2] / "secubox-sbxos"
E, C = Path(__file__).resolve().parents[1] / "sbxos" / "espaces.toml", SBXOS / "www" / "mine" / "curation.json"


def mods(r):
    return {x["id"]: x for e in r["espaces"] for x in e["modules"]}


@pytest.mark.parametrize("role", ["guest", "user", "admin"])
@pytest.mark.parametrize("lan", [True, False])
def test_matrice(role, lan):
    r = sm.construire(role, lan, "exemple.test", E, C)
    ms = mods(r)
    assert r["role"] == role and r["lan"] is lan
    if role == "guest":
        assert set(ms) <= {"radio", "billets", "peertube", "metanews"}
    if not lan:
        assert not any(x["lan"] for x in ms.values())
        assert "zigbee" not in ms
    if role == "guest" or not lan:
        assert all("etat" not in x for x in ms.values())
    assert r["capacites"]["zigbee_commande"] is False
    assert "gk2" not in json.dumps(r)


def test_personne_lan_voit_tout_avec_etat():
    ms = mods(sm.construire("user", True, "exemple.test", E, C))
    assert "zigbee" in ms and ms["zigbee"]["etat"] == "inconnu"
    assert ms["nextcloud"]["url"].endswith("/sbx/entrer")
    assert all(x["url"] is None or x["url"].startswith("https://") and ".exemple.test/" in x["url"] for x in ms.values())


def test_route_en_tetes_et_invite(monkeypatch):
    orig = sm.construire
    monkeypatch.setattr(sm, "construire", lambda role, lan, dom: orig(role, lan, dom, E, C))
    monkeypatch.setattr("secubox_core.auth.domaine_box", lambda: "exemple.test")
    r = TestClient(m.app).get("/sbxos/manifeste", headers={"X-SecuBox-LAN": "1"})
    assert r.status_code == 200
    assert r.headers["cache-control"] == "private, no-store" and r.headers["vary"] == "Cookie"
    assert r.json()["role"] == "guest" and r.json()["domaine"] == "exemple.test"


def test_photoprism_s_ouvre_par_l_entree_oidc_du_hall():
    """#2255 : PhotoPrism n'a pas de /sbx/entrer ; il s'ouvre par son départ OIDC, qui renvoie à l'IdP du Hall (compte créé à la première connexion)."""
    ms = mods(sm.construire("user", True, "exemple.test", E, C))
    assert ms["photoprism"]["url"] == "https://photoprism.exemple.test/api/v1/oidc/login"
