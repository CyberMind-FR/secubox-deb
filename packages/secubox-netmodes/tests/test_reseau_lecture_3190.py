# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3190 — lecture du réseau : ports, clients, carte (fonctions pures sur des sorties ip -j / bridge -j)."""
import ast
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main, reseau_api, reseau_lecture  # noqa: E402

from secubox_core.auth import require_lecture  # noqa: E402

MAC_BOX = "f0:ad:4e:27:88:9a"
IP_LINK = [
    {"ifname": "eth0", "flags": ["BROADCAST", "MULTICAST"], "operstate": "DOWN", "address": "f0:ad:4e:27:88:98"},
    {"ifname": "eth1", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP", "address": MAC_BOX},
    {"ifname": "eth2", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP", "address": "f0:ad:4e:27:88:9b"},
    {"ifname": "lan0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP", "master": "br-lan", "address": MAC_BOX},
    {"ifname": "lan1", "flags": ["BROADCAST", "MULTICAST", "UP"], "operstate": "DOWN", "master": "br-lan", "address": MAC_BOX},
    {"ifname": "lan2", "flags": ["BROADCAST", "MULTICAST"], "operstate": "DOWN", "address": MAC_BOX},
    {"ifname": "lan3", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP", "master": "br-lan", "address": MAC_BOX},
    {"ifname": "br-lan", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP", "address": MAC_BOX},
]
FDB = [
    {"mac": "d4:93:90:27:a7:dd", "ifname": "lan0", "flags": [], "master": "br-lan", "state": ""},
    {"mac": "dc:a6:32:e6:74:e1", "ifname": "lan3", "flags": [], "master": "br-lan", "state": ""},
    {"mac": MAC_BOX, "ifname": "lan0", "flags": [], "master": "br-lan", "state": "permanent"},
    {"mac": MAC_BOX, "ifname": "lan3", "flags": [], "master": "br-lan", "state": ""},          # MAC de la box apprise : exclue
    {"mac": "33:33:00:00:00:01", "ifname": "lan0", "flags": ["self"], "state": "permanent"},
]
SYSFS = {
    "lan0": {"carrier": "1", "speed": "1000", "operstate": "up"},
    "lan1": {"carrier": "0", "speed": "-1", "operstate": "down"},
    "lan3": {"carrier": "1", "speed": "100", "operstate": "up"},
    "eth2": {"carrier": "1", "speed": "1000", "operstate": "up"},
}
BAUX = "1793051869 d4:93:90:27:a7:dd 192.168.42.192 pop-os 01:d4:93:90:27:a7:dd\n"
MACS_BOX = {MAC_BOX}


def _ports(**kw):
    a = dict(ip_link=IP_LINK, fdb=FDB, sysfs=SYSFS, coupes=set(), macs_box=MACS_BOX)
    a.update(kw)
    return {p["nom"]: p for p in reseau_lecture.ports(**a)}


def test_roles_exacts():
    assert reseau_lecture.ROLES == {"eth2": "wan", "eth1": "conduit", "eth0": "sfp",
                                    "lan0": "lan", "lan1": "lan", "lan2": "lan", "lan3": "lan"}
    p = _ports()
    assert {n: p[n]["role"] for n in p} == reseau_lecture.ROLES


def test_port_lan0_forme():
    p = _ports()["lan0"]
    assert p == {"nom": "lan0", "role": "lan", "porteuse": True, "vitesse_mbps": 1000, "etat_admin": "up",
                 "maitre": "br-lan", "macs": ["d4:93:90:27:a7:dd"], "plusieurs_appareils": False, "coupe": False}


def test_mac_de_la_box_exclue_et_permanentes():
    p = _ports()
    assert p["lan3"]["macs"] == ["dc:a6:32:e6:74:e1"]
    assert all(MAC_BOX not in x["macs"] for x in p.values())


def test_vitesse_moins_un_ou_illisible_none():
    p = _ports()
    assert p["lan1"]["vitesse_mbps"] is None and p["lan1"]["porteuse"] is False
    assert p["lan2"]["vitesse_mbps"] is None and p["lan2"]["porteuse"] is None      # rien dans sysfs


def test_etat_admin_et_coupe():
    p = _ports(coupes={"lan1"})
    assert p["lan1"]["coupe"] is True and p["lan0"]["coupe"] is False
    assert p["lan2"]["etat_admin"] == "down" and p["lan0"]["etat_admin"] == "up"


def test_plusieurs_appareils_a_deux_mac():
    fdb = FDB + [{"mac": "aa:bb:cc:00:00:01", "ifname": "lan0", "flags": [], "master": "br-lan", "state": ""}]
    p = _ports(fdb=fdb)["lan0"]
    assert p["plusieurs_appareils"] is True and len(p["macs"]) == 2


def test_eth2_wan_sans_action():
    p = _ports()["eth2"]
    assert p["role"] == "wan" and p["coupe"] is False and p["macs"] == []


def test_client_bail_et_port_depuis_fdb():
    c = reseau_lecture.clients(BAUX, FDB, [])
    assert c == [{"mac": "d4:93:90:27:a7:dd", "ip": "192.168.42.192", "nom": "pop-os", "port": "lan0",
                  "source": "bail", "expire": 1793051869}]


def test_voisin_sans_bail():
    voisins = [{"dst": "192.168.42.192", "lladdr": "d4:93:90:27:a7:dd", "state": ["REACHABLE"]},
               {"dst": "192.168.42.50", "lladdr": "dc:a6:32:e6:74:e1", "state": ["STALE"]},
               {"dst": "192.168.42.51", "state": ["FAILED"]}]
    c = {x["mac"]: x for x in reseau_lecture.clients(BAUX, FDB, voisins)}
    assert len(c) == 2 and c["d4:93:90:27:a7:dd"]["source"] == "bail"
    v = c["dc:a6:32:e6:74:e1"]
    assert v == {"mac": "dc:a6:32:e6:74:e1", "ip": "192.168.42.50", "nom": "", "port": "lan3",
                 "source": "voisin", "expire": None}


def test_bail_ligne_invalide_ignoree():
    assert reseau_lecture.clients("n'importe quoi\n\n", FDB, []) == []


def test_carte():
    c = reseau_lecture.carte(
        [{"ifname": "eth2", "addr_info": [{"family": "inet", "local": "192.168.1.200", "prefixlen": 24}]}],
        [{"dst": "default", "gateway": "192.168.1.254", "dev": "eth2"}],
        [{"dst": "192.168.1.254", "lladdr": "00:07:cb:aa:bb:cc", "state": ["REACHABLE"]}],
        [{"ifname": "vethA"}, {"ifname": "vethB"}],
        [{"ifname": "wg-mesh", "flags": ["POINTOPOINT", "UP", "LOWER_UP"]}, {"ifname": "wg-toolbox", "flags": ["POINTOPOINT"]}])
    assert c == {"wan": {"interface": "eth2", "adresse": "192.168.1.200/24", "passerelle": "192.168.1.254",
                         "voisins": [{"ip": "192.168.1.254", "mac": "00:07:cb:aa:bb:cc"}]},
                 "lxc": {"pont": "br-lxc", "actifs": 2},
                 "tunnels": [{"nom": "wg-mesh", "etat": "up"}, {"nom": "wg-toolbox", "etat": "down"}]}


# ---- lire_systeme : sources en échec ----------------------------------------------------------------------------

def _faux_run(echecs=()):
    def run(argv, **kw):
        assert kw.get("timeout") and not kw.get("shell")
        if any(t in " ".join(argv) for t in echecs):
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")
    return run


def test_source_en_echec_pannes_et_cle_none(monkeypatch):
    reseau_api._cache.clear()
    monkeypatch.setattr(reseau_api.subprocess, "run", _faux_run(echecs=("fdb",)))
    s = reseau_api.lire_systeme()
    assert "fdb" in s["pannes"] and s["fdb"] is None and s["ip_link"] == []


def test_aucune_panne_liste_vide(monkeypatch, tmp_path):
    reseau_api._cache.clear()
    (tmp_path / "baux").write_text(BAUX)
    monkeypatch.setattr(reseau_api, "BAUX", tmp_path / "baux")
    monkeypatch.setattr(reseau_api, "RESEAU_D", tmp_path)
    monkeypatch.setattr(reseau_api.subprocess, "run", _faux_run())
    assert reseau_api.lire_systeme()["pannes"] == []


def test_lire_systeme_aucune_action_sur_interface(monkeypatch):
    reseau_api._cache.clear()
    vus = []

    def run(argv, **kw):
        vus.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")
    monkeypatch.setattr(reseau_api.subprocess, "run", run)
    reseau_api.lire_systeme()
    for argv in vus:
        assert argv[0] in ("ip", "bridge") and "sudo" not in argv
        assert not set(argv) & {"set", "add", "del", "flush", "replace", "up", "down"}


# ---- routes -----------------------------------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    sysd = {"ip_link": IP_LINK, "fdb": FDB, "voisins_lan": [], "wan_addr": [], "route_defaut": [], "voisins_wan": [],
            "membres_lxc": [], "liens_wg": [], "sysfs": SYSFS, "baux": BAUX, "coupes": set(), "pannes": []}
    monkeypatch.setattr(reseau_api, "lire_systeme", lambda: dict(sysd))
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    yield TestClient(main.app, base_url="http://testserver")
    main.app.dependency_overrides.clear()


def test_routes_lecture(client):
    r = client.get("/reseau/ports")
    assert r.status_code == 200 and {p["nom"] for p in r.json()["ports"]} == set(reseau_lecture.ROLES)
    assert client.get("/reseau/clients").json()["clients"][0]["port"] == "lan0"
    assert client.get("/reseau/carte").json()["carte"]["lxc"]["pont"] == "br-lxc"


def test_routes_gardees_require_lecture():
    src = Path(reseau_api.__file__).read_text()
    arbre = ast.parse(src)
    routes = [f for f in arbre.body if isinstance(f, ast.FunctionDef)
              and any(isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "get" for d in f.decorator_list)]
    assert len(routes) == 3
    for f in routes:
        assert "require_lecture" in ast.unparse(f.args), f.name


def test_pas_de_subprocess_dans_async_def():
    for mod in (reseau_api, reseau_lecture):
        for n in ast.walk(ast.parse(Path(mod.__file__).read_text())):
            if isinstance(n, ast.AsyncFunctionDef):
                assert "subprocess" not in ast.unparse(n)


def test_lecture_pure_sans_subprocess():
    assert "subprocess" not in Path(reseau_lecture.__file__).read_text()


def test_anonyme_sans_acteur(client):
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}
    for chemin in ("/reseau/ports", "/reseau/clients", "/reseau/carte"):
        assert "acteur" not in client.get(chemin).text
