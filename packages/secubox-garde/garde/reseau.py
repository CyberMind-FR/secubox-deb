# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Vue réseau de la box pour secubox-garde (#3794) : adresses jamais touchées et préfixes du LAN.

Tout vient de `ip -j` (sans root) :
- protégées : adresses de la box (toutes interfaces), passerelle par défaut (Freebox), voisins des
  ponts LXC (`lxcbr*`, = conteneurs), réseaux des interfaces WireGuard (`wg*`, plage du maillage) ;
- `lan_prefixes` : préfixes IPv6 globaux des interfaces de la box hors `lo`, `wg*`, `lxcbr*`, `veth*`,
  tout préfixe plus large que /48 refusé.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
from typing import Callable, List, Tuple

_EXCLUES = ("lo", "wg", "lxcbr", "veth")


def _ip_j(args) -> str:
    return subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=10,
                           check=False).stdout


def _json(runner, args) -> list:
    try:
        d = json.loads(runner(args) or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    return d if isinstance(d, list) else []


def lire(runner: Callable = _ip_j) -> Tuple[Callable[[str], bool], List[str]]:
    """Rend `(protegees(ip) -> bool, lan_prefixes)`."""
    adresses, reseaux, prefixes = set(), [], []
    for itf in _json(runner, ["addr"]):
        nom = str(itf.get("ifname") or "")
        for a in itf.get("addr_info") or []:
            try:
                ip = ipaddress.ip_address(a.get("local"))
                net = ipaddress.ip_network(f"{a.get('local')}/{int(a.get('prefixlen'))}", strict=False)
            except (ValueError, TypeError):
                continue
            adresses.add(ip)
            if nom.startswith("wg"):
                reseaux.append(net)
            elif (not nom.startswith(_EXCLUES) and ip.version == 6 and ip.is_global
                  and net.prefixlen >= 48):
                prefixes.append(str(net))
    for r in _json(runner, ["route", "show", "default"]) + _json(runner, ["-6", "route", "show", "default"]):
        try:
            adresses.add(ipaddress.ip_address(r.get("gateway")))
        except (ValueError, TypeError):
            pass
    for n in _json(runner, ["neigh"]):
        if str(n.get("dev") or "").startswith("lxcbr"):
            try:
                adresses.add(ipaddress.ip_address(n.get("dst")))
            except (ValueError, TypeError):
                pass

    def protegees(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return a in adresses or any(a.version == n.version and a in n for n in reseaux)

    return protegees, sorted(set(prefixes))
