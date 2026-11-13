# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3688 — matériel réel du panneau Réseau : détection sur des arborescences /sys simulées (MOCHAbin, ESPRESSObin,
Raspberry Pi, PC), aucune décision par un nom ou un modèle de carte, et lire_systeme qui, sur une carte routeur, lit
EXACTEMENT les mêmes sources qu'avant (rien ne change), et sur une carte sans switch ni WAN dédié, ne lance pas les
lectures du WAN eth2 et de br-lan (sans objet, jamais « en panne »)."""
import ast
import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main, materiel, reseau_api, reseau_lecture  # noqa: E402

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

import sysfs_simule  # noqa: E402

ICI = Path(__file__).resolve().parents[1]
# Les huit lectures d'avant #3688, à l'identique (argv compris).
SOURCES_AVANT = {
    "ip_link": ["ip", "-j", "link"],
    "fdb": ["bridge", "-j", "fdb", "show", "br", "br-lan"],
    "voisins_lan": ["ip", "-j", "neigh", "show", "dev", "br-lan"],
    "wan_addr": ["ip", "-j", "-4", "addr", "show", "dev", "eth2"],
    "route_defaut": ["ip", "-j", "-4", "route", "show", "default"],
    "voisins_wan": ["ip", "-j", "neigh", "show", "dev", "eth2"],
    "membres_lxc": ["ip", "-j", "link", "show", "master", "br-lxc"],
    "liens_wg": ["ip", "-j", "link", "show", "type", "wireguard"],
}
# Sorties `ip -j` relevées sur gk7 (Raspberry Pi 4) le 2026-11-12, adresses remplacées par des adresses de documentation.
ADRESSES_RPI = [
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.128", "prefixlen": 24, "scope": "global"},
                                     {"family": "inet6", "local": "2001:db8::dea6:32ff:fe64:f596", "prefixlen": 64, "scope": "global"},
                                     {"family": "inet6", "local": "fe80::dea6:32ff:fe64:f596", "prefixlen": 64, "scope": "link"}]},
    {"ifname": "br-lxc", "addr_info": [{"family": "inet", "local": "10.100.0.1", "prefixlen": 24, "scope": "global"}]},
    {"ifname": "wlan0", "addr_info": []},
    {"ifname": "wg-mesh", "addr_info": [{"family": "inet", "local": "10.10.0.2", "prefixlen": 24, "scope": "global"}]},
]
ROUTE_RPI = [{"dst": "default", "gateway": "192.0.2.254", "dev": "eth0", "protocol": "dhcp", "prefsrc": "192.0.2.128"}]


# ── Détection pure ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def _genres(m):
    return {i["nom"]: i["genre"] for i in m["interfaces"]}


def test_mochabin_switch_dsa_et_wan_dedie(tmp_path):
    m = materiel.lire(sysfs_simule.mochabin(tmp_path))
    assert m["switch_dsa"] is True and m["wan_dedie"] is True and m["vue_routeur"] is True and m["pannes"] == []
    assert _genres(m) == {"eth0": "filaire", "eth1": "conduit_switch", "eth2": "filaire",
                          "lan0": "port_switch", "lan1": "port_switch", "lan2": "port_switch", "lan3": "port_switch"}


def test_espressobin_switch_dsa_et_port_wan(tmp_path):
    m = materiel.lire(sysfs_simule.espressobin(tmp_path))
    assert m["switch_dsa"] is True and m["wan_dedie"] is True and m["vue_routeur"] is True
    assert _genres(m) == {"eth0": "conduit_switch", "wan": "port_switch", "lan0": "port_switch", "lan1": "port_switch"}


def test_raspberry_pi_sans_switch_ni_wan_dedie(tmp_path):
    m = materiel.lire(sysfs_simule.rpi(tmp_path))
    assert (m["switch_dsa"], m["wan_dedie"], m["pont_lan"], m["vue_routeur"]) == (False, False, False, False)
    assert m["interfaces"] == [
        {"nom": "eth0", "genre": "filaire", "etat": "up", "porteuse": True, "vitesse_mbps": 1000},
        {"nom": "wlan0", "genre": "wifi", "etat": "down", "porteuse": None, "vitesse_mbps": None}]   # porteuse illisible : None


def test_raspberry_pi_avec_br_lan_garde_la_vue_routeur(tmp_path):
    """br-lan présent (mode routeur appliqué) : rien de ce qui le concerne n'est masqué."""
    m = materiel.lire(sysfs_simule.rpi(tmp_path, br_lan=True))
    assert m["switch_dsa"] is False and m["wan_dedie"] is False and m["pont_lan"] is True and m["vue_routeur"] is True


def test_pc_une_ou_deux_prises_ethernet(tmp_path):
    une = tmp_path / "a"
    sysfs_simule._iface(une, "enp1s0")
    sysfs_simule._virtuelles(une)
    assert materiel.lire(une / "class" / "net")["vue_routeur"] is False
    deux = tmp_path / "b"
    sysfs_simule._iface(deux, "enp1s0")
    sysfs_simule._iface(deux, "enp2s0")
    assert materiel.lire(deux / "class" / "net")["wan_dedie"] is True


def test_sysfs_illisible_ne_decide_jamais_sans_routeur(tmp_path):
    m = materiel.lire(tmp_path / "absent")
    assert m["vue_routeur"] is None and m["interfaces"] is None and m["pannes"] == ["sysfs"]


def test_le_modele_s_affiche_mais_ne_decide_rien(tmp_path):
    """Aucun nom de carte ne décide : un modèle « MOCHAbin » sur le matériel d'un RPi reste sans routeur, et inversement."""
    f = tmp_path / "model"
    f.write_bytes(b"Globalscale Marvell ARMADA 7040 MOCHAbin board\x00")
    m = materiel.lire(sysfs_simule.rpi(tmp_path / "r"), (tmp_path / "absent", f))
    assert m["modele"] == "Globalscale Marvell ARMADA 7040 MOCHAbin board" and m["vue_routeur"] is False
    f.write_bytes(b"Raspberry Pi 4 Model B Rev 1.1\x00")
    m = materiel.lire(sysfs_simule.mochabin(tmp_path / "m"), (f,))
    assert m["modele"] == "Raspberry Pi 4 Model B Rev 1.1" and m["vue_routeur"] is True
    # Chaînes du code (docstrings exclues) : aucun nom de carte, de box ni de port ne peut décider.
    arbre = ast.parse(Path(materiel.__file__).read_text())
    docs = {id(n.body[0].value) for n in ast.walk(arbre) if isinstance(n, (ast.Module, ast.FunctionDef))
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    chaines = " ".join(n.value for n in ast.walk(arbre) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                       and id(n) not in docs).lower()
    for nom in ("mochabin", "espressobin", "raspberry", "armada", "7040", "3720", "gk", "eth", "lan0", "wlan0"):   # DEVTYPE « wlan » du noyau admis
        assert nom not in chaines, nom


def test_completer_adresses_globales_et_passerelle(tmp_path):
    m = materiel.completer(materiel.lire(sysfs_simule.rpi(tmp_path)), ADRESSES_RPI, ROUTE_RPI)
    eth0, wlan0 = m["interfaces"]
    assert eth0["adresses"] == ["192.0.2.128/24", "2001:db8::dea6:32ff:fe64:f596/64"] and eth0["passerelle"] == "192.0.2.254"
    assert wlan0["adresses"] == [] and wlan0["passerelle"] is None and m["pannes"] == []
    m = materiel.completer(materiel.lire(sysfs_simule.rpi(tmp_path / "x")), None, None)
    assert all(i["adresses"] is None and i["passerelle"] is None for i in m["interfaces"])
    assert m["pannes"] == ["adresses", "route_defaut"]


# ── lire_systeme et routes ───────────────────────────────────────────────────────────────────────────────────────────────────
def _systeme(monkeypatch, tmp_path, racine, baux=True):
    reseau_api._cache.clear()
    vus = []
    if baux:
        (tmp_path / "baux").write_text("1 aa:bb:cc:dd:ee:01 192.0.2.50 poste *\n")
    monkeypatch.setattr(reseau_api, "BAUX", tmp_path / "baux")
    monkeypatch.setattr(reseau_api, "RESEAU_D", tmp_path)
    monkeypatch.setattr(reseau_api, "SYS_MATERIEL", racine)

    def run(argv, **kw):
        assert kw.get("timeout") and kw.get("capture_output") and not kw.get("shell")
        vus.append(list(argv))
        sortie = {tuple(reseau_api.SOURCES["adresses"]): ADRESSES_RPI,
                  tuple(reseau_api.SOURCES["route_defaut"]): ROUTE_RPI}.get(tuple(argv), [])
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(sortie), stderr="")
    monkeypatch.setattr(reseau_api.subprocess, "run", run)
    return vus


@pytest.mark.parametrize("carte", ["mochabin", "espressobin"])
def test_carte_routeur_lit_les_memes_sources_qu_avant(monkeypatch, tmp_path, carte):
    """MOCHAbin et ESPRESSObin : les huit lectures d'avant, mêmes argv, plus la seule lecture des adresses ; baux lus ;
    rien « sans objet »."""
    vus = _systeme(monkeypatch, tmp_path, getattr(sysfs_simule, carte)(tmp_path / "sys"))
    s = reseau_api.lire_systeme()
    assert vus == list(SOURCES_AVANT.values()) + [["ip", "-j", "addr", "show"]]
    assert {k: v for k, v in reseau_api.SOURCES.items() if k != "adresses"} == SOURCES_AVANT
    assert s["sans_objet"] == [] and s["pannes"] == [] and s["baux"].startswith("1 aa:bb")
    assert s["materiel"]["vue_routeur"] is True
    reseau_api._cache.clear()


def test_raspberry_pi_ne_lance_pas_les_lectures_du_routeur(monkeypatch, tmp_path):
    vus = _systeme(monkeypatch, tmp_path, sysfs_simule.rpi(tmp_path / "sys"))
    s = reseau_api.lire_systeme()
    lancees = {k for k, argv in reseau_api.SOURCES.items() if argv in vus}
    assert lancees == {"ip_link", "route_defaut", "membres_lxc", "liens_wg", "adresses"}
    assert s["sans_objet"] == ["fdb", "voisins_lan", "wan_addr", "voisins_wan", "baux"] and s["pannes"] == []
    assert s["baux"] is None                                                      # le fichier existe, il n'est pas lu
    assert s["materiel"]["interfaces"][0]["passerelle"] == "192.0.2.254"
    reseau_api._cache.clear()


@pytest.fixture
def client():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "alice"}
    yield TestClient(main.app, base_url="http://testserver")
    main.app.dependency_overrides.clear()
    reseau_api._cache.clear()


def test_routes_sur_mochabin_inchangees_et_materiel_en_plus(monkeypatch, tmp_path, client):
    _systeme(monkeypatch, tmp_path, sysfs_simule.mochabin(tmp_path / "sys"))
    r = client.get("/reseau/carte").json()
    assert r["carte"] == reseau_lecture.carte([], ROUTE_RPI, [], [], []) and r["pannes"] == [] and r["sans_objet"] == []
    assert r["materiel"]["vue_routeur"] is True and r["materiel"]["switch_dsa"] is True
    assert client.get("/reseau/materiel").json()["materiel"] == r["materiel"]
    assert client.get("/reseau/ports").json()["sans_objet"] == [] and client.get("/reseau/clients").json()["sans_objet"] == []


def test_routes_sur_raspberry_pi_sans_objet_jamais_en_panne(monkeypatch, tmp_path, client):
    _systeme(monkeypatch, tmp_path, sysfs_simule.rpi(tmp_path / "sys"))
    r = client.get("/reseau/carte").json()
    assert r["carte"]["wan"] is None and r["pannes"] == [] and r["sans_objet"] == ["wan_addr", "voisins_wan"]
    m = client.get("/reseau/materiel").json()["materiel"]
    assert m["vue_routeur"] is False and [i["nom"] for i in m["interfaces"]] == ["eth0", "wlan0"]
    assert m["interfaces"][0]["adresses"][0] == "192.0.2.128/24"
    c = client.get("/reseau/clients").json()
    assert c["clients"] is None and c["pannes"] == [] and c["sans_objet"] == ["fdb", "voisins_lan", "baux"]


def test_route_materiel_gardee_et_profil_apparmor_couvre_sysfs():
    src = Path(reseau_api.__file__).read_text()
    assert 'def lire_materiel(_user: Any = Depends(require_lecture))' in src
    profil = (ICI / "apparmor" / "secubox-netmodes").read_text()
    for regle in ("/sys/class/net/** r,", "/sys/devices/**/net/** r,", "/proc/device-tree/model r,"):
        assert regle in profil
    assert "subprocess" not in Path(materiel.__file__).read_text()
