# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Garde du SSH de gitea (2222) : LAN et maillage seulement (#1791).

Le port 2222 menait au SSH du conteneur gitea quelle que soit la source. La
table générée doit admettre la boucle, les sous-réseaux privés reliés, le
maillage et le tunnel d'administration — et rien d'autre.
"""
import importlib.machinery
import importlib.util
import ipaddress
import pathlib

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-gitea-ssh-garde"
_loader = importlib.machinery.SourceFileLoader("garde", str(SCRIPT))
_spec = importlib.util.spec_from_loader("garde", _loader)
G = importlib.util.module_from_spec(_spec)
_loader.exec_module(G)


def _itf(nom, *cidrs):
    return {"ifname": nom, "addr_info": [
        {"family": "inet", "local": c.split("/")[0], "prefixlen": int(c.split("/")[1])} for c in cidrs]}


# Les interfaces de gk2 (2026-10-01), plus un lien public et un pont podman.
GK2 = [
    _itf("lo", "127.0.0.1/8", "192.168.255.1/24"),
    _itf("eth1", "172.16.0.250/24"),
    _itf("eth2", "192.168.1.200/24"),
    _itf("eye-br0", "10.55.0.1/24"),
    _itf("br-lxc", "10.100.0.1/24"),
    _itf("wg-toolbox", "10.99.1.1/24"),
    _itf("wg-admin", "10.98.0.1/24"),
    _itf("wg-mesh", "10.10.0.1/24"),
    _itf("wg-ephemeral", "10.11.0.1/24"),
    _itf("podman0", "10.88.0.1/16"),
    _itf("vethABC", "10.200.0.1/24"),
    _itf("enp9s0", "203.0.113.7/24"),
]


def _admis(reseaux, ip):
    return any(ipaddress.ip_address(ip) in n for n in reseaux)


def test_lan_maillage_admin_et_boucle_admis():
    s = G.sources(GK2)
    for ip in ("127.0.0.1", "192.168.1.3", "10.10.0.5", "10.98.0.2", "10.100.0.40", "172.16.0.9"):
        assert _admis(s, ip), ip


def test_visiteurs_publics_et_conteneurs_hors_lxc_refuses():
    s = G.sources(GK2)
    for ip in ("10.99.1.7",      # wg-toolbox : tunnels de visiteurs
               "10.11.0.9",      # wg-ephemeral
               "10.88.0.4",      # pont podman (vestige)
               "10.200.0.2",     # veth
               "203.0.113.50",   # sous-réseau PUBLIC relié : jamais admis
               "198.51.100.1", "8.8.8.8"):
        assert not _admis(s, ip), ip


def test_echec_ferme_sans_adresse():
    assert G.sources([]) == [ipaddress.ip_network("127.0.0.0/8")]
    assert G.sources(None) == [ipaddress.ip_network("127.0.0.0/8")]


def test_adresses_malformees_ignorees():
    s = G.sources([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "x"},
                                                   {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}])
    assert s == [ipaddress.ip_network("127.0.0.0/8")]


def test_table_jette_avant_la_traduction():
    t = G.table(G.sources(GK2))
    assert "table inet secubox_gitea_ssh" in t
    assert "hook prerouting priority -150" in t, "doit passer AVANT la DNAT (dstnat = -100)"
    assert "tcp dport 2222 fib daddr type local ip saddr != @sources4 counter drop" in t
    assert "meta nfproto ipv6 tcp dport 2222" in t
    assert "192.168.1.0/24" in t and "10.10.0.0/24" in t
    assert "10.99.1.0/24" not in t and "flush ruleset" not in t


def test_lignes_systemd_et_paquet():
    racine = SCRIPT.parents[1]
    rules = (racine / "debian" / "rules").read_text()
    for u in ("secubox-gitea-ssh-garde.service", "secubox-gitea-ssh-garde-maj.service",
              "secubox-gitea-ssh-garde-maj.timer"):
        assert (racine / "systemd" / u).is_file(), u
        assert u in rules, u
    svc = (racine / "systemd" / "secubox-gitea-ssh-garde.service").read_text()
    assert "PartOf=nftables.service" in svc and "ReloadPropagatedFrom=nftables.service" in svc
    assert "secubox-gitea-ssh-garde.service" in (racine / "debian" / "postinst").read_text()
