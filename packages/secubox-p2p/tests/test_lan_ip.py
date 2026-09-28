# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""L'adresse annoncée par les invitations de maillage (#1554)."""
from api.main import choisit_lan_ip

# Les interfaces réelles de gk2 le 2026-09-28, avec 192.168.255.1 sur lo.
GK2 = [("lo", "127.0.0.1"), ("lo", "192.168.255.1"), ("eth1", "172.16.0.250"), ("eth2", "192.168.1.200"),
       ("eye-br0", "10.55.0.1"), ("br-lxc", "10.100.0.1"), ("lxcbr0", "10.0.3.1"), ("wg-mesh", "10.10.0.1")]


def test_gk2_annonce_son_adresse_lan_pas_celle_de_lo():
    assert choisit_lan_ip(GK2, "192.168.1.200") == "192.168.1.200"


def test_mode_routeur_la_passerelle_du_lan_passe_devant():
    # La box EST la passerelle : 192.168.255.1 sur br-lan, sortie par le WAN.
    a = [("lo", "127.0.0.1"), ("br-lan", "192.168.255.1"), ("eth0", "82.64.1.2")]
    assert choisit_lan_ip(a, "82.64.1.2") == "192.168.255.1"


def test_sans_route_par_defaut_une_adresse_privee_reelle():
    assert choisit_lan_ip([("lo", "127.0.0.1"), ("wg-mesh", "10.10.0.5"), ("enp0s31f6", "192.168.1.9")], None) == "192.168.1.9"


def test_jamais_le_maillage_ni_un_conteneur():
    assert choisit_lan_ip([("wg-mesh", "10.10.0.5"), ("br-lxc", "10.100.0.1")], None) is None


def test_mdns_lit_l_annonce_secubox(monkeypatch):
    """L'annonce publiée par secubox-annuaire-noms est lue (#1556)."""
    import asyncio
    from api import main as m
    ligne = ('=;eth0;IPv4;SecuBox gk3;_secubox._tcp;local;gk3.local;192.168.1.9;443;'
             '"mesh_ip=10.10.0.5" "node_id=sbx-38c2ec6a7580" "boxname=gk3"\n')

    class P:
        async def communicate(self):
            return ligne.encode(), b""

    async def faux(*a, **k):
        return P()
    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", faux)
    pairs = asyncio.run(m.discover_mdns(1))
    assert pairs[0]["boxname"] == "gk3" and pairs[0]["name"] == "gk3"
    assert pairs[0]["id"] == "sbx-38c2ec6a7580" and pairs[0]["mesh_ip"] == "10.10.0.5"
    assert pairs[0]["address"] == "192.168.1.9"
