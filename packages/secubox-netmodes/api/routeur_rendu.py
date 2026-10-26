# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rendu des fichiers du mode routeur (#3189) : fonction pure, sans effet de bord."""
from __future__ import annotations

from .routeur_config import ConfigRouteur

MARQUE = "GÉNÉRÉ par secubox-netmodes"
COMMENTAIRE_NFT = "secubox netmodes lan"
TABLE_NFT = "secubox_netmodes_lan"

CHEMINS: dict[str, str] = {
    "netdev": "/etc/systemd/network/05-secubox-br-lan.netdev",
    "pont": "/etc/systemd/network/05-secubox-br-lan.network",
    "ports": "/etc/systemd/network/05-secubox-lan-ports.network",
    "dhcp": "/var/lib/secubox-netmodes/lan-dhcp.conf",  # lu brut par dnsmasq root : arbre root seul
    "unbound": "/etc/unbound/unbound.conf.d/95-secubox-lan-routeur.conf",
    "nft": "/etc/nftables.d/zz-secubox-netmodes-lan.nft",
    "geo": "/etc/nginx/secubox-lan-geo.d/netmodes-lan.conf",
}

_ENTETE = f"# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# {MARQUE}\n"


def rendre(cfg: ConfigRouteur) -> dict[str, str]:
    ip = cfg.adresse.ip
    reseau = cfg.adresse.network
    wan = cfg.wan
    sortie = {
        "netdev": "[NetDev]\nName=br-lan\nKind=bridge\n\n[Bridge]\nSTP=no\n",
        "pont": (
            "[Match]\nName=br-lan\n\n"
            f"[Network]\nAddress={cfg.adresse}\nConfigureWithoutCarrier=yes\nIPv6AcceptRA=no\n"
        ),
        "ports": f"[Match]\nName={' '.join(cfg.ports)}\n\n[Network]\nBridge=br-lan\n",
        # DHCP seul : le DNS reste à Unbound (port=0)
        "dhcp": (
            "port=0\ninterface=br-lan\nbind-interfaces\nexcept-interface=lo\n"
            "dhcp-authoritative\n"
            f"dhcp-range={cfg.dhcp_debut},{cfg.dhcp_fin},{reseau.netmask},{cfg.bail}\n"
            f"dhcp-option=option:router,{ip}\n"
            f"dhcp-option=option:dns-server,{ip}\n"
            "dhcp-leasefile=/var/lib/misc/dnsmasq.leases\nuser=dnsmasq\n"
        ),
        # ip-freebind : au démarrage Unbound peut précéder l'adresse de br-lan ; sans lui il ne démarre pas du tout
        "unbound": f"server:\n    ip-freebind: yes\n    interface: {ip}\n    access-control: {reseau} allow\n",
        "nft": (
            # seul moyen d'ouvrir un port dans la chaîne input en policy drop
            f'add rule inet filter input iifname "br-lan" udp dport 67 accept comment "{COMMENTAIRE_NFT} dhcp"\n'
            f'add rule inet filter input iifname "br-lan" udp dport 53 accept comment "{COMMENTAIRE_NFT} dns"\n'
            f'add rule inet filter input iifname "br-lan" tcp dport 53 accept comment "{COMMENTAIRE_NFT} dns-tcp"\n'
            # créer puis supprimer : idiome idempotent au rechargement
            f"table inet {TABLE_NFT}\n"
            f"delete table inet {TABLE_NFT}\n"
            f"table inet {TABLE_NFT} {{\n"
            "    chain forward {\n"
            "        type filter hook forward priority filter - 2; policy accept;\n"
            f'        iifname "{wan}" oifname "br-lan" ct state established,related accept\n'
            f'        iifname "{wan}" oifname "br-lan" drop comment "{COMMENTAIRE_NFT} : rien de neuf du WAN vers le LAN"\n'
            "    }\n"
            "    chain postrouting {\n"
            "        type nat hook postrouting priority srcnat; policy accept;\n"
            f'        ip saddr {reseau} oifname "{wan}" masquerade comment "{COMMENTAIRE_NFT} nat"\n'
            "    }\n"
            "}\n"
        ),
        "geo": f"{reseau} 1;\n",
    }
    return {k: _ENTETE + v for k, v in sortie.items()}
