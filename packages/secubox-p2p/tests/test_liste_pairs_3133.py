# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — le maître publie la liste de ses pairs vivants (liens WireGuard directs entre pairs).

wg_mesh.json peut contenir des clones périmés (même endpoint, plusieurs clés) : seuls les pairs à poignée de main
récente sont publiés, dédoublonnés par clé, et chaque champ est validé strictement (donnée écrite par les enrôlements)."""
import base64
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import main
from api import pairs_directs as pd

MAINTENANT = 1_000_000.0
CONF = Path(__file__).resolve().parents[1] / "nginx" / "p2p-masterlink.conf"


def cle(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def pair(n, nom=None, ip=None, endpoint=None, **plus):
    p = {
        "public_key": cle(n),
        "allowed_ips": f"10.10.0.{n}/32",
        "mesh_ip": ip or f"10.10.0.{n}",
        "name": nom or f"box{n}",
        "endpoint": endpoint or f"192.168.1.{n}:51820",
    }
    p.update(plus)
    return p


def etat_gk2():
    """Sept entrées : trois vivantes, deux clones périmés, une doublon de clé, une sans poignée."""
    return {"peers": [
        pair(2), pair(3), pair(4),
        pair(5, nom="clone-vieux"),                  # poignée > 10 min
        pair(6, nom="clone-absent"),                 # aucune poignée
        pair(4, nom="doublon-de-4"),                 # même clé que box4
        pair(7, nom="box7-sans-endpoint", endpoint="inconnu"),
    ], "private_key": "SECRET"}


POIGNEES = {cle(2): MAINTENANT - 5, cle(3): MAINTENANT - 599, cle(4): MAINTENANT - 30,
            cle(5): MAINTENANT - 601, cle(7): MAINTENANT - 1}


def test_seuls_les_vivants_sans_doublon():
    liste = pd.liste_publiable(etat_gk2(), POIGNEES, MAINTENANT)
    assert [p["mesh_ip"] for p in liste] == ["10.10.0.2", "10.10.0.3", "10.10.0.4"]
    assert [p["nom"] for p in liste] == ["box2", "box3", "box4"]
    assert set(liste[0]) == {"nom", "mesh_ip", "cle_publique", "endpoint"}
    assert "SECRET" not in repr(liste)


def test_doublon_garde_la_poignee_la_plus_recente_des_entrees():
    etat = {"peers": [pair(4, nom="ancien"), pair(4, nom="recent")]}
    # une seule clé, donc une seule poignée : la première entrée valide est gardée, une seule fois
    liste = pd.liste_publiable(etat, {cle(4): MAINTENANT - 1}, MAINTENANT)
    assert len(liste) == 1


@pytest.mark.parametrize("mauvais", [
    pair(8, endpoint="8.8.8.8:51822"),
    pair(8, endpoint="192.168.1.8:51820\nPersistentKeepalive = 1"),
    pair(8, endpoint="192.168.1.8:51820\n"),
    pair(8, endpoint="10.10.0.8:51820"),
    pair(8, endpoint="192.168.1.8:0"),
    pair(8, endpoint="192.168.1.8:70000"),
    pair(8, endpoint=["192.168.1.8:51820"]),
    pair(8, nom="box\nx"),
    pair(8, nom="box8\n"),
    pair(8, nom="Box8"),
    pair(8, nom="-box"),
    pair(8, nom="a" * 32),
    pair(8, ip="10.10.1.8"),
    pair(8, ip="10.10.0.8\n"),
    pair(8, ip=["10.10.0.8"]),
    {**pair(8), "public_key": "pas-une-cle"},
    {**pair(8), "allowed_ips": "10.10.0.0/24"},
    "pas un dict", None, 42,
])
def test_entrees_invalides_ecartees(mauvais):
    poignees = {cle(8): MAINTENANT - 1}
    assert pd.liste_publiable({"peers": [mauvais]}, poignees, MAINTENANT) == []


def test_poignees_inexploitables_valent_non_vivant():
    etat = {"peers": [pair(2)]}
    for ts in ("12", None, "abc", [], float("nan")):
        assert pd.liste_publiable(etat, {cle(2): ts}, MAINTENANT) == []
    assert pd.liste_publiable(etat, None, MAINTENANT) == []
    assert pd.liste_publiable({"peers": "x"}, POIGNEES, MAINTENANT) == []
    assert pd.liste_publiable("x", POIGNEES, MAINTENANT) == []


def test_plafond_32_et_tri_par_ip():
    peers = [pair(n) for n in range(2, 60)]
    poignees = {cle(n): MAINTENANT - 1 for n in range(2, 60)}
    liste = pd.liste_publiable({"peers": list(reversed(peers))}, poignees, MAINTENANT)
    assert len(liste) == 32
    ips = [tuple(map(int, p["mesh_ip"].split("."))) for p in liste]
    assert ips == sorted(ips)


def test_valider_pair_normalise():
    v = pd.valider_pair(pair(9))
    assert v == {"nom": "box9", "mesh_ip": "10.10.0.9", "cle_publique": cle(9), "endpoint": "192.168.1.9:51820"}
    assert pd.valider_pair(pair(9), reseau="10.20.0.0/24") is None


# --- route -----------------------------------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")     # le mode tableau de bord du poste ne doit pas ouvrir la route
    monkeypatch.setattr(main, "get_wg_mesh_config", etat_gk2)
    monkeypatch.setattr(main.mesh, "load_handshakes", lambda *a, **k: dict(POIGNEES, **{cle(5): 1.0}))
    return TestClient(main.app)


def test_route_avec_en_tete_pair_sans_jeton(client, monkeypatch):
    monkeypatch.setattr(pd.time, "time", lambda: MAINTENANT)
    r = client.get("/master-link/pairs", headers={"X-SecuBox-Pair": "1"})
    assert r.status_code == 200
    corps = r.json()
    assert corps["version"] == 1
    assert [p["nom"] for p in corps["pairs"]] == ["box2", "box3", "box4"]


@pytest.mark.parametrize("entetes", [{}, {"X-SecuBox-Pair": "0"}, {"X-SecuBox-Pair": "true"}, {"X-SecuBox-Pair": " 1x"}])
def test_route_refusee_sans_pair_ni_session(client, entetes):
    assert client.get("/master-link/pairs", headers=entetes).status_code in (401, 403)


def test_route_session_de_lecture(client, monkeypatch):
    async def lecteur(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(main, "require_lecture", lecteur)
    monkeypatch.setattr(pd.time, "time", lambda: MAINTENANT)
    assert client.get("/master-link/pairs").status_code == 200


# --- nginx -----------------------------------------------------------------------------------------------------

def test_nginx_pose_l_en_tete_pair_depuis_la_carte_geo():
    texte = CONF.read_text()
    assert re.search(r"geo\s+\$remote_addr\s+\$p2p_pair_maille\s*\{[^}]*default\s+0;[^}]*10\.10\.0\.0/24\s+1;", texte, re.S)
    assert "proxy_set_header X-SecuBox-Pair $p2p_pair_maille;" in texte
    assert "X-SecuBox-LAN" in texte
