# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2857 — le panneau Réseau du hub : le WAN est l'interface de la ROUTE PAR DÉFAUT, pas une interface devinée par son nom.

Constat sur gk2 : « Sortie Internet disconnected, Adresse WAN N/A, Adresse LAN 10.100.0.1 » alors que la box avait Internet. Son WAN est eth2 (DHCP) et son pont br-lxc (conteneurs)
passait pour le LAN."""
import importlib

M = importlib.import_module("api.main")


def _addr(nom, *ips, flags=("UP",)):
    return {"ifname": nom, "flags": list(flags), "addr_info": [{"family": "inet", "local": ip} for ip in ips]}


GK2 = [_addr("lo", "127.0.0.1"), _addr("eth2", "192.168.1.200"), _addr("br-lxc", "10.100.0.1"), _addr("lxcbr0", "10.0.3.1"), _addr("wg-mesh", "10.10.0.1")]
ROUTE_GK2 = [{"dst": "default", "gateway": "192.168.1.254", "dev": "eth2"}]


def test_le_wan_est_l_interface_de_la_route_par_defaut():
    r = M.resume_reseau(GK2, ROUTE_GK2)
    assert r["wan_status"] == "connected" and r["wan_ip"] == "192.168.1.200"


def test_un_pont_de_conteneurs_n_est_pas_le_lan():
    r = M.resume_reseau(GK2, ROUTE_GK2)
    assert r["lan_ip"] == "N/A", r


def test_un_vrai_pont_lan_est_le_lan():
    r = M.resume_reseau(GK2 + [_addr("br-lan", "192.168.10.1")], ROUTE_GK2)
    assert r["lan_ip"] == "192.168.10.1" and r["wan_ip"] == "192.168.1.200"


def test_sans_route_par_defaut_la_sortie_est_deconnectee():
    r = M.resume_reseau(GK2, [])
    assert r["wan_status"] == "disconnected" and r["wan_ip"] == "N/A"


def test_route_par_defaut_sur_une_interface_sans_adresse_est_deconnectee():
    r = M.resume_reseau([_addr("eth0")], [{"dst": "default", "dev": "eth0"}])
    assert r["wan_status"] == "disconnected" and r["wan_ip"] == "N/A"


def test_carte_unique_eth0_reste_connectee():
    r = M.resume_reseau([_addr("lo", "127.0.0.1"), _addr("eth0", "192.168.1.67")], [{"dst": "default", "dev": "eth0"}])
    assert r["wan_status"] == "connected" and r["wan_ip"] == "192.168.1.67"


def test_entrees_illisibles_ne_font_pas_planter():
    r = M.resume_reseau(None, None)
    assert r["wan_status"] == "disconnected" and r["lan_ip"] == "N/A" and r["wan_ip"] == "N/A"
