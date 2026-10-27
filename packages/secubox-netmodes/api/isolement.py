# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Isoler un port du commutateur (#3201) : rendu pur des fichiers d'un port isolé, sans effet de bord.

Un port isolé sort du pont br-lan et porte son propre /24 pris dans la réserve 192.168.248.0/22 (un /24 par
port, dans l'ordre de PORTS_LAN). Il ne voit que l'Internet : ni le LAN, ni les autres ports isolés, ni les
réseaux privés. Le contrôleur root écrit ces fichiers ; ce module ne touche à rien."""
from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from .routeur_config import PORTS_LAN, RESERVE_ISOLES
from .routeur_rendu import MARQUE

RESERVE = RESERVE_ISOLES
BAIL = "2h"
COMMENTAIRE = "secubox netmodes isole"       # jamais « secubox netmodes lan » : le retour arrière du routeur l'efface
DOSSIER_DHCP = "/var/lib/secubox-netmodes/dhcp.d"

CHEMINS: dict[str, str] = {
    "network": "/etc/systemd/network/04-secubox-port-{port}-isole.network",
    "dhcp": DOSSIER_DHCP + "/isole-{port}.conf",
    "nft": "/etc/nftables.d/zz-secubox-netmodes-isole-{port}.nft",
}

_ENTETE = f"# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# {MARQUE}\n"
_WAN = re.compile(r"^eth[0-9]$")
# réseaux privés, CGNAT et lien-local : un port isolé n'y atteint rien
_PRIVES = "10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16"


def _verifier_port(port: str) -> None:
    if port not in PORTS_LAN:
        raise ValueError(f"port « {port} » refusé : seuls {', '.join(PORTS_LAN)} peuvent être isolés")


def passerelle(port: str) -> IPv4Interface:
    """lan0 → 192.168.248.1/24 … lan3 → 192.168.251.1/24."""
    _verifier_port(port)
    rang = PORTS_LAN.index(port)
    return IPv4Interface(f"{IPv4Network(RESERVE).network_address + 256 * rang + 1}/24")


PASSERELLES: tuple[IPv4Address, ...] = tuple(passerelle(p).ip for p in PORTS_LAN)


def table(port: str) -> str:
    _verifier_port(port)
    return f"secubox_netmodes_isole_{port}"


def chemins(port: str) -> dict[str, str]:
    _verifier_port(port)
    return {cle: modele.format(port=port) for cle, modele in CHEMINS.items()}


def rendre(port: str, wan: str) -> dict[str, str]:
    _verifier_port(port)
    if not isinstance(wan, str) or not _WAN.fullmatch(wan):
        raise ValueError(f"wan « {wan} » invalide : attendu ethN (un chiffre)")
    gw = passerelle(port)
    ip, reseau = gw.ip, gw.network
    debut, fin = reseau.network_address + 100, reseau.network_address + 199
    com = f"{COMMENTAIRE} {port}"
    t = table(port)
    sortie = {
        "network": (
            f"[Match]\nName={port}\n\n"
            f"[Network]\nAddress={gw}\nConfigureWithoutCarrier=yes\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n"
        ),
        # DHCP seul, étiqueté : port=, user= et dhcp-leasefile= restent dans lan-dhcp.conf
        "dhcp": (
            f"interface={port}\n"
            f"dhcp-range=set:isole-{port},{debut},{fin},{reseau.netmask},{BAIL}\n"
            f"dhcp-option=tag:isole-{port},option:router,{ip}\n"
            f"dhcp-option=tag:isole-{port},option:dns-server,{ip}\n"
        ),
        "nft": (
            # seul moyen d'ouvrir un port dans la chaîne input en policy drop
            f'add rule inet filter input iifname "{port}" udp dport 67 accept comment "{com} dhcp"\n'
            f'add rule inet filter input iifname "{port}" udp dport 53 accept comment "{com} dns"\n'
            f'add rule inet filter input iifname "{port}" tcp dport 53 accept comment "{com} dns-tcp"\n'
            # créer puis supprimer : idiome idempotent au rechargement
            f"table inet {t}\n"
            f"delete table inet {t}\n"
            f"table inet {t} {{\n"
            "    chain input {\n"
            "        type filter hook input priority filter - 3; policy accept;\n"
            f'        iifname "{port}" ct state established,related accept\n'
            f'        iifname "{port}" udp dport {{ 53, 67 }} accept\n'
            f'        iifname "{port}" tcp dport 53 accept\n'
            f'        iifname "{port}" drop comment "{com} : rien d\'autre vers la box"\n'
            "    }\n"
            "    chain forward {\n"
            "        type filter hook forward priority filter - 3; policy accept;\n"
            f'        iifname "{port}" oifname != "{wan}" drop comment "{com} : sortie par le WAN seulement"\n'
            f'        iifname "{port}" meta nfproto ipv6 drop comment "{com} : pas d\'IPv6"\n'
            f'        iifname "{port}" ip daddr {{ {_PRIVES} }} drop comment "{com} : pas de réseau privé"\n'
            f'        oifname "{port}" ct state established,related accept\n'
            f'        oifname "{port}" drop comment "{com} : rien de neuf vers le port"\n'
            "    }\n"
            "    chain postrouting {\n"
            "        type nat hook postrouting priority srcnat; policy accept;\n"
            f'        ip saddr {reseau} oifname "{wan}" masquerade comment "{com} nat"\n'
            "    }\n"
            "}\n"
        ),
    }
    return {k: _ENTETE + v for k, v in sortie.items()}
