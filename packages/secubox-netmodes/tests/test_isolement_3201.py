# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Isoler un port du commutateur (#3201) : test du rendu pur, sans effet de bord."""
from ipaddress import IPv4Interface

import pytest

from api import isolement as iso
from api import routeur_rendu as rr
from api.routeur_config import ErreurConfig, depuis_dict

CFG42 = {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100",
         "dhcp_fin": "192.168.42.199", "bail": "12h",
         "ports": ["lan0", "lan1", "lan2", "lan3"], "wan": "eth2"}
ENTETE = "# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# GÉNÉRÉ par secubox-netmodes\n"


@pytest.fixture
def sortie():
    return iso.rendre("lan2", "eth2")


def corps(texte):
    assert texte.startswith(ENTETE)
    return texte[len(ENTETE):].splitlines()


def test_passerelles():
    assert iso.passerelle("lan0") == IPv4Interface("192.168.248.1/24")
    assert iso.passerelle("lan3") == IPv4Interface("192.168.251.1/24")
    assert iso.passerelle("lan2") == IPv4Interface("192.168.250.1/24")
    assert [str(p) for p in iso.PASSERELLES] == [f"192.168.{n}.1" for n in range(248, 252)]
    for mauvais in ("eth2", "br-lan", "lan4"):
        with pytest.raises(ValueError):
            iso.passerelle(mauvais)


def test_constantes_et_chemins():
    assert iso.BAIL == "2h"
    assert iso.COMMENTAIRE == "secubox netmodes isole"
    assert iso.table("lan2") == "secubox_netmodes_isole_lan2"
    assert iso.chemins("lan2") == {
        "network": "/etc/systemd/network/04-secubox-port-lan2-isole.network",
        "dhcp": "/var/lib/secubox-netmodes/dhcp.d/isole-lan2.conf",
        "nft": "/etc/nftables.d/zz-secubox-netmodes-isole-lan2.nft",
    }


def test_marque_en_tete(sortie):
    assert set(sortie) == {"network", "dhcp", "nft"}
    for contenu in sortie.values():
        assert contenu.startswith(ENTETE)


def test_network(sortie):
    n = sortie["network"]
    assert "[Match]\nName=lan2\n" in n
    for attendu in ("Address=192.168.250.1/24", "ConfigureWithoutCarrier=yes",
                    "IPv6AcceptRA=no", "LinkLocalAddressing=no"):
        assert attendu in n
    assert "Bridge=" not in n
    assert "eth" not in n


def test_dhcp(sortie):
    assert corps(sortie["dhcp"]) == [
        "interface=lan2",
        "dhcp-range=set:isole-lan2,192.168.250.100,192.168.250.199,255.255.255.0,2h",
        "dhcp-option=tag:isole-lan2,option:router,192.168.250.1",
        "dhcp-option=tag:isole-lan2,option:dns-server,192.168.250.1",
    ]
    for interdit in ("port=", "user=", "dhcp-leasefile="):
        assert interdit not in sortie["dhcp"]


def test_nft_entree(sortie):
    nft = sortie["nft"]
    for proto, port, nom in (("udp", 67, "dhcp"), ("udp", 53, "dns"), ("tcp", 53, "dns-tcp")):
        assert (f'add rule inet filter input iifname "lan2" {proto} dport {port} accept '
                f'comment "secubox netmodes isole lan2 {nom}"\n') in nft
    assert ("table inet secubox_netmodes_isole_lan2\n"
            "delete table inet secubox_netmodes_isole_lan2\n"
            "table inet secubox_netmodes_isole_lan2 {\n") in nft
    entree = nft.split("chain input {")[1].split("    }\n")[0]
    assert "type filter hook input priority filter - 3;" in entree
    lignes = [l.strip() for l in entree.splitlines()]
    cibles = [
        'iifname "lan2" ct state established,related accept',
        'iifname "lan2" udp dport { 53, 67 } accept',
        'iifname "lan2" tcp dport 53 accept',
        'iifname "lan2" drop',
    ]
    positions = [next(i for i, l in enumerate(lignes) if l.startswith(c)) for c in cibles]
    assert positions == sorted(positions)


def test_nft_transit(sortie):
    nft = sortie["nft"]
    transit = nft.split("chain forward {")[1].split("    }\n")[0]
    assert "type filter hook forward priority filter - 3;" in transit
    lignes = [l.strip() for l in transit.splitlines()]
    cibles = [
        'iifname "lan2" oifname != "eth2" drop',
        'iifname "lan2" meta nfproto ipv6 drop',
        'iifname "lan2" ip daddr { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } drop',
        'oifname "lan2" ct state established,related accept',
        'oifname "lan2" drop',
    ]
    positions = [next(i for i, l in enumerate(lignes) if l.startswith(c)) for c in cibles]
    assert positions == sorted(positions)
    nat = nft.split("chain postrouting {")[1]
    assert "type nat hook postrouting priority srcnat;" in nat
    assert 'ip saddr 192.168.250.0/24 oifname "eth2" masquerade' in nat


def test_aucun_commentaire_du_lan():
    # le retour arrière du routeur supprime les règles dont le commentaire commence par « secubox netmodes lan »
    for port in iso.PORTS_LAN:
        nft = iso.rendre(port, "eth2")["nft"]
        commentaires = [c.split('"')[0] for c in nft.split('comment "')[1:]]
        assert commentaires
        for c in commentaires:
            assert c.startswith(f"secubox netmodes isole {port}")
            assert not c.startswith("secubox netmodes lan")


@pytest.mark.parametrize("wan", ["eth2; drop", "br-lan", "eth22", ""])
def test_wan_refuse(wan):
    with pytest.raises(ValueError):
        iso.rendre("lan2", wan)


def test_port_hors_liste_refuse():
    with pytest.raises(ValueError):
        iso.rendre("eth2", "eth2")


def test_unbound_ecoute_les_passerelles():
    u = rr.rendre(depuis_dict(CFG42))["unbound"]
    lignes = u.splitlines()
    gel = lignes.index("    ip-freebind: yes")
    for n in range(248, 252):
        assert lignes.index(f"    interface: 192.168.{n}.1") > gel
    assert "    access-control: 192.168.248.0/22 allow" in lignes
    assert "    interface: 192.168.42.1" in lignes
    assert "    access-control: 192.168.42.0/24 allow" in lignes
    assert [f"    interface: {p}" for p in iso.PASSERELLES] == [
        l for l in lignes if l.startswith("    interface: 192.168.2")]


def test_lan_dans_la_reserve_refuse():
    for adresse, debut, fin in (("192.168.249.1/24", "192.168.249.100", "192.168.249.199"),
                                ("192.168.250.1/23", "192.168.250.100", "192.168.251.199")):
        with pytest.raises(ErreurConfig, match="réservé aux ports isolés"):
            depuis_dict({"adresse": adresse, "dhcp_debut": debut, "dhcp_fin": fin})
