# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : aucune exposition externe tant que le mot de passe par défaut est actif ; refus explicite, rien d'écrit."""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-haproxy" / "composants" / "exposure"))


@pytest.fixture
def c(tmp_path, monkeypatch):
    import api.reach as r
    import api.main as m
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path / "snip")
    monkeypatch.setattr(m, "_reload_nginx", lambda: True)

    async def _rien(*a, **k):
        return None
    monkeypatch.setattr(m, "_apply_tor", _rien)
    monkeypatch.setattr(m._mdp_defaut, "actif", lambda *a, **k: True)
    monkeypatch.setattr(m._mdp_defaut, "audit", lambda *a, **k: None)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(m.app)
    c.snip = tmp_path / "snip"
    return c


def test_wan_refuse_sans_rien_ecrire(c):
    r = c.post("/exposure/z.example", json={"reach": "wan", "mesh": False, "tor": False})
    assert r.status_code == 409 and "mot de passe par défaut" in r.json()["detail"]
    assert not (c.snip / "z.example.conf").exists()


def test_tor_refuse(c):
    assert c.post("/exposure/z.example", json={"reach": "lan", "mesh": False, "tor": True}).status_code == 409


def test_lan_reste_permis(c):
    assert c.post("/exposure/z.example", json={"reach": "lan", "mesh": False, "tor": False}).status_code == 200


@pytest.mark.parametrize("chemin,corps", [("/tor/add", {"service": "x", "local_port": 80, "onion_port": 80}),
                                          ("/ssl/add", {"service": "x", "domain": "x.example", "local_port": 80}),
                                          ("/emancipate", {"service": "x", "port": 80, "tor": True})])
def test_autres_chemins_d_exposition_refuses(c, chemin, corps):
    assert c.post(chemin, json=corps).status_code == 409


def test_emancipate_webui_refuse(c):
    assert c.post("/tor/emancipate_webui").status_code == 409
