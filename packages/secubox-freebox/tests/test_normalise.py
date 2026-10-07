# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Connecteur Freebox — réponses Freebox OS normalisées pour l'affichage : lisibles, sans adresse MAC complète, tolérantes aux champs absents."""
from api import normalise as n

HOTES = [
    {"id": "ether-d4:93:90:27:a7:dd", "primary_name": "Pixel-8", "host_type": "smartphone", "vendor_name": "Google, Inc.", "active": True,
     "reachable": True, "last_activity": 1791300000, "l2ident": {"id": "D4:93:90:27:A7:DD", "type": "mac_address"},
     "names": [{"name": "Pixel-8", "source": "dhcp"}],
     "l3connectivities": [{"addr": "192.168.1.20", "af": "ipv4", "active": True, "reachable": True},
                          {"addr": "2a01:e0a:dec:c4e0:1:2:3:4", "af": "ipv6", "active": True, "reachable": True},
                          {"addr": "fe80::1", "af": "ipv6", "active": True, "reachable": True}]},
    {"id": "ether-38:07:16:93:4e:95", "primary_name": "", "host_type": "freebox_player", "vendor_name": "Freebox SAS", "active": False,
     "reachable": False, "l2ident": {"id": "38:07:16:93:4E:95", "type": "mac_address"}, "names": [{"name": "Freebox-Player-POP", "source": "mdns"}],
     "l3connectivities": []},
    {"id": "sans-l2", "primary_name": "Fantôme", "l3connectivities": None},
]


def test_les_appareils_sont_normalises_sans_adresse_mac_complete():
    a = n.appareils(HOTES)
    assert len(a) == 2                                                   # l'entrée sans adresse MAC est écartée
    pixel = a[0]
    assert pixel["nom"] == "Pixel-8" and pixel["type"] == "smartphone" and pixel["fabricant"] == "Google, Inc."
    assert pixel["ipv4"] == ["192.168.1.20"] and pixel["ipv6_publiques"] == ["2a01:e0a:dec:c4e0:1:2:3:4"]
    assert pixel["actif"] is True and pixel["mac_fin"] == "27:a7:dd" and len(pixel["id"]) == 10
    assert "d4:93:90:27:a7:dd" not in repr(a).lower()


def test_un_appareil_sans_nom_principal_prend_son_premier_nom_connu():
    a = n.appareils(HOTES)[1]
    assert a["nom"] == "Freebox-Player-POP" and a["actif"] is False and a["ipv4"] == [] and a["ipv6_publiques"] == []


def test_les_actifs_passent_en_premier():
    a = n.appareils(HOTES)
    assert [x["actif"] for x in a] == [True, False]


def test_la_connexion_est_resumee_en_clair():
    conn = {"type": "ethernet", "state": "up", "media": "ftth", "ipv4": "82.67.100.75", "ipv6": "2a01:e0a::1",
            "bandwidth_down": 8_000_000_000, "bandwidth_up": 4_000_000_000, "rate_down": 1500, "rate_up": 200}
    cfg = {"ipv6_enabled": True, "ipv6_firewall": True, "delegations": [{"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": ""}]}
    r = n.connexion(conn, cfg)
    assert r["en_ligne"] is True and r["media"] == "ftth" and r["ipv4_publique"] == "82.67.100.75"
    assert r["debit_max_descendant_mbit"] == 8000 and r["debit_max_montant_mbit"] == 4000
    assert r["ipv6_actif"] is True and r["pare_feu_ipv6"] is True and r["prefixes_ipv6"] == ["2a01:e0a:dec:c4e0::/64"]


def test_une_connexion_coupee_ou_incomplete_ne_plante_pas():
    assert n.connexion({"state": "down"}, {})["en_ligne"] is False
    r = n.connexion({}, {})
    assert r["pare_feu_ipv6"] is None and r["ipv6_actif"] is None and r["prefixes_ipv6"] == []


REDIRS = [
    {"id": 3, "enabled": True, "ip_proto": "tcp", "wan_port_start": 443, "wan_port_end": 443, "lan_ip": "192.168.1.200", "lan_port": 443,
     "src_ip": "0.0.0.0", "comment": "SecuBox web", "hostname": "gk2"},
    {"id": 4, "enabled": False, "ip_proto": "tcp", "wan_port_start": 2200, "wan_port_end": 2210, "lan_ip": "192.168.1.50", "lan_port": 22,
     "src_ip": "0.0.0.0", "comment": ""},
    {"id": 5, "enabled": True, "ip_proto": "tcp", "wan_port_start": 3389, "wan_port_end": 3389, "lan_ip": "192.168.1.60", "lan_port": 3389},
]


def test_les_redirections_sont_normalisees_et_les_ports_sensibles_signales():
    r = n.redirections(REDIRS)
    assert [x["id"] for x in r] == [3, 4, 5]
    assert r[0] == {"id": 3, "actif": True, "protocole": "tcp", "port_externe_debut": 443, "port_externe_fin": 443, "appareil_ip": "192.168.1.200",
                    "port_local": 443, "source": "tout Internet", "commentaire": "SecuBox web", "nom_appareil": "gk2", "sensible": False}
    assert r[1]["sensible"] is True and r[2]["sensible"] is True          # SSH exposé via 2200-2210 vers le port 22 ; bureau à distance
    assert r[2]["commentaire"] == "" and r[2]["nom_appareil"] == ""


def test_une_source_restreinte_est_nommee():
    r = n.redirections([{"id": 1, "enabled": True, "ip_proto": "tcp", "wan_port_start": 80, "wan_port_end": 80, "lan_ip": "192.168.1.5",
                         "lan_port": 80, "src_ip": "203.0.113.7"}])
    assert r[0]["source"] == "203.0.113.7"


def test_exceptions_ipv6_sont_normalisees_comme_les_redirections():
    r = n.exceptions_ipv6([{"id": "a", "enabled": True, "ip_proto": "tcp", "ip": "2a01:e0a:dec:c4e0::200", "port_start": 443, "port_end": 443, "comment": "web"},
                           {"id": "b", "enabled": False, "ip_proto": "tcp", "ip": "2a01:e0a::5", "port_start": 22, "port_end": 22}])
    assert r[0] == {"id": "a", "actif": True, "protocole": "tcp", "appareil": "2a01:e0a:dec:c4e0::200", "port_debut": 443, "port_fin": 443,
                    "commentaire": "web", "sensible": False}
    assert r[1]["sensible"] is True and r[1]["actif"] is False


def test_les_ports_sensibles_sont_connus():
    for p in (21, 22, 23, 139, 445, 3306, 3389, 5900):
        assert n.est_sensible(p, p)
    assert not n.est_sensible(443, 443) and not n.est_sensible(80, 80)
    assert n.est_sensible(20, 25)                    # une plage qui contient un port sensible l'est
