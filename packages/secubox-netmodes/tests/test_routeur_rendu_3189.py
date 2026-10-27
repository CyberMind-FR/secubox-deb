# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rendu des fichiers du mode routeur (#3189)."""
import shutil
import subprocess

import pytest

from api import routeur_rendu as rr
from api.routeur_config import depuis_dict

CFG42 = {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100",
         "dhcp_fin": "192.168.42.199", "bail": "12h",
         "ports": ["lan0", "lan1", "lan2", "lan3"], "wan": "eth2"}


@pytest.fixture
def sortie():
    return rr.rendre(depuis_dict(CFG42))


def lignes(texte):
    return texte.splitlines()


def test_cles_et_constantes(sortie):
    assert set(sortie) == set(rr.CHEMINS)
    assert rr.CHEMINS["nft"] == "/etc/nftables.d/zz-secubox-netmodes-lan.nft"
    assert rr.CHEMINS["geo"] == "/etc/nginx/secubox-lan-geo.d/netmodes-lan.conf"
    # lu brut par dnsmasq lancé en root : arbre root seul, pas /etc/secubox (propriété de secubox)
    assert rr.CHEMINS["dhcp"] == "/var/lib/secubox-netmodes/lan-dhcp.conf"
    assert rr.COMMENTAIRE_NFT == "secubox netmodes lan"
    assert rr.TABLE_NFT == "secubox_netmodes_lan"


def test_marque_en_tete(sortie):
    for cle, contenu in sortie.items():
        l = lignes(contenu)
        assert l[0] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0", cle
        assert l[1] == "# " + rr.MARQUE, cle


def test_netdev(sortie):
    l = lignes(sortie["netdev"])
    for x in ("Name=br-lan", "Kind=bridge", "STP=no"):
        assert x in l


def test_pont(sortie):
    l = lignes(sortie["pont"])
    for x in ("[Match]", "Name=br-lan", "Address=192.168.42.1/24",
              "ConfigureWithoutCarrier=yes", "IPv6AcceptRA=no"):
        assert x in l


def test_ports(sortie):
    l = lignes(sortie["ports"])
    assert "Name=lan0 lan1 lan2 lan3" in l
    assert "Bridge=br-lan" in l


@pytest.mark.parametrize("ports,wan,adr", [
    (["lan0", "lan1", "lan2", "lan3"], "eth2", "192.168.42.1/24"),
    (["lan1"], "eth0", "10.77.0.1/24"),
    (["lan0", "lan3"], "eth1", "172.20.5.1/24"),
])
def test_aucun_eth_dans_les_name(ports, wan, adr):
    base = adr.rsplit(".", 1)[0]
    cfg = depuis_dict({"adresse": adr, "dhcp_debut": base + ".100",
                       "dhcp_fin": base + ".199", "ports": ports, "wan": wan})
    out = rr.rendre(cfg)
    for cle in ("netdev", "pont", "ports"):
        for l in lignes(out[cle]):
            if l.startswith("Name="):
                assert "eth" not in l


def test_dhcp(sortie):
    l = lignes(sortie["dhcp"])
    for x in ("port=0", "interface=br-lan", "bind-dynamic", "except-interface=lo",
              "dhcp-authoritative",
              "dhcp-range=192.168.42.100,192.168.42.199,255.255.255.0,12h",
              "dhcp-option=option:router,192.168.42.1",
              "dhcp-option=option:dns-server,192.168.42.1",
              "dhcp-leasefile=/var/lib/misc/dnsmasq.leases", "user=dnsmasq"):
        assert x in l
    assert "conf-dir" not in sortie["dhcp"]
    # #3201 : un port isolé sans adresse (encore, ou plus) ne doit pas arrêter dnsmasq pour tout le LAN
    assert "bind-interfaces" not in l
    assert "no-ping" not in sortie["dhcp"]


def test_unbound(sortie):
    l = lignes(sortie["unbound"])
    assert "server:" in l
    assert "    interface: 192.168.42.1" in l
    assert "    access-control: 192.168.42.0/24 allow" in l


def test_nft(sortie):
    nft = sortie["nft"]
    for proto, port, suf in (("udp", 67, "dhcp"), ("udp", 53, "dns"), ("tcp", 53, "dns-tcp")):
        attendu = (f'add rule inet filter input iifname "br-lan" {proto} dport {port} '
                   f'accept comment "secubox netmodes lan {suf}"')
        assert attendu in lignes(nft)
    l = [x.strip() for x in lignes(nft)]
    i = l.index("table inet secubox_netmodes_lan")
    assert l[i + 1] == "delete table inet secubox_netmodes_lan"
    assert l[i + 2] == "table inet secubox_netmodes_lan {"
    assert nft.index("add rule") < nft.index("delete table")
    assert "type filter hook forward priority filter - 2; policy accept;" in nft
    assert "type nat hook postrouting priority srcnat; policy accept;" in nft
    ok = 'iifname "eth2" oifname "br-lan" ct state established,related accept'
    ko = 'iifname "eth2" oifname "br-lan" drop'
    assert ok in nft and ko in nft and nft.index(ok) < nft.index(ko)
    assert 'comment "secubox netmodes lan : rien de neuf du WAN vers le LAN"' in nft
    assert 'ip saddr 192.168.42.0/24 oifname "eth2" masquerade comment "secubox netmodes lan nat"' in nft


def test_geo(sortie):
    assert "192.168.42.0/24 1;" in lignes(sortie["geo"])


def test_nft_valide(sortie, tmp_path):
    if not shutil.which("nft"):
        pytest.skip("nft absent")
    f = tmp_path / "t.nft"
    f.write_text("table inet filter { chain input { type filter hook input priority filter; policy drop; } }\n"
                 + sortie["nft"])
    r = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True, timeout=20)
    if r.returncode != 0 and ("Operation not permitted" in r.stderr or "Permission denied" in r.stderr):
        pytest.skip("droits insuffisants pour nft -c")
    assert r.returncode == 0, r.stderr


def test_unbound_ip_freebind(sortie):
    """Relecture finale I2 : au démarrage, Unbound peut précéder l'adresse de br-lan ; sans ip-freebind il refuse de
    démarrer (DNS de toute la box perdu). Même réglage que le drop-in IPv6 de dns-lan."""
    unbound = lignes(sortie["unbound"])
    i = unbound.index("server:")
    assert "    ip-freebind: yes" in unbound[i + 1:]
    assert unbound.index("    ip-freebind: yes") < unbound.index("    interface: 192.168.42.1")
