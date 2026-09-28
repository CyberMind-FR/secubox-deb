# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox_core.reseau — l'adresse LAN d'une box (#1554, #1556)
CyberMind — https://cybermind.fr

UNE règle, partagée : l'adresse qu'une AUTRE machine du LAN peut joindre.
Les invitations de maillage (p2p), l'annonce Bonjour et les noms
<box>.lan.<zone> (annuaire) la lisent ici — trois copies finiraient par
diverger, et c'est précisément une copie fausse (192.168.255.1 posée sur lo)
qui envoyait gk3 vers une adresse injoignable.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import Iterable, List, Optional, Tuple

# Interfaces qui ne sont PAS le LAN : bouclage, conteneurs, tunnels, maillage.
IFACES_HORS_LAN = ("lo", "veth", "docker", "lxcbr", "br-lxc", "wg", "tun", "tap", "virbr", "eye-br")


def choisit_lan_ip(adresses: Iterable[Tuple[str, str]], source_defaut: Optional[str]) -> Optional[str]:
    """`adresses` : [(interface, ip)]. Ordre : 192.168.255.x sur une interface
    RÉELLE (mode routeur : la box est la passerelle du LAN), puis la source de
    la route par défaut, puis toute adresse privée d'une interface réelle."""
    reelles = [(i, ip) for i, ip in adresses
               if not i.startswith(IFACES_HORS_LAN) and not ip.startswith("127.")]
    for _, ip in reelles:
        if ip.startswith("192.168.255."):
            return ip
    if source_defaut and any(ip == source_defaut for _, ip in reelles):
        return source_defaut
    for _, ip in reelles:
        try:
            if ipaddress.ip_address(ip).is_private:
                return ip
        except ValueError:
            continue
    return reelles[0][1] if reelles else source_defaut


def adresses_ipv4() -> List[Tuple[str, str]]:
    out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    return [(m.group(1), m.group(2))
            for m in re.finditer(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)]


def source_route_defaut() -> Optional[str]:
    r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5).stdout
    m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", r)
    return m.group(1) if m else None


def lan_ip() -> Optional[str]:
    """L'adresse LAN de CETTE box, ou None. Jamais d'exception."""
    try:
        return choisit_lan_ip(adresses_ipv4(), source_route_defaut())
    except Exception:  # noqa: BLE001 — une adresse d'affichage ne doit rien casser
        return None
