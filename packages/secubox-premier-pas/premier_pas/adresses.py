# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Où continuer l'assistant dans un navigateur (#3424).

La version web de l'assistant est servie par nginx sous `/premier-pas/` (secubox.d/premier-pas.conf), derrière HAProxy en TLS sur le port 443 :
l'URL est donc `https://<nom ou IPv4>/premier-pas/`, sans port. Ce module ne lit que les adresses de la box : aucun secret, aucune dépendance
(`ip -j addr`, repli sur /proc/net/fib_trie inutile : une liste vide vaut « pas d adresse encore »).
"""
from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from typing import Callable, List, Optional, Tuple

CHEMIN = "/premier-pas/"
# Interfaces internes : jamais proposées à un humain devant un navigateur.
INTERNES = ("lo", "br-lxc", "lxcbr", "docker", "wg-", "wg", "veth", "virbr", "cni", "podman", "tun", "tap")


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _interne(nom: str) -> bool:
    return any(nom == p or nom.startswith(p) for p in INTERNES)


def _ip_json() -> str:
    return subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, timeout=3, check=False).stdout


def ipv4_utiles(lecteur: Callable[[], str] = _ip_json) -> List[str]:
    """IPv4 utiles, LAN (privées) d'abord puis le reste (WAN), sans doublon.
    `lecteur` rend la sortie JSON de `ip -j -4 addr` (injectable pour les tests)."""
    try:
        data = json.loads(lecteur() or "[]")
    except (ValueError, OSError, subprocess.SubprocessError):
        return []
    lan: List[str] = []
    wan: List[str] = []
    for itf in data if isinstance(data, list) else []:
        if not isinstance(itf, dict) or _interne(str(itf.get("ifname", ""))):
            continue
        for a in itf.get("addr_info") or []:
            try:
                ip = ipaddress.IPv4Address(a.get("local", ""))
            except (ValueError, AttributeError):
                continue
            if a.get("family", "inet") != "inet" or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                continue
            cible = lan if any(ip in r for r in _RFC1918) else wan
            if str(ip) not in lan + wan:
                cible.append(str(ip))
    return lan + wan


def nom_hote(lecteur: Callable[[], str] = socket.gethostname) -> str:
    try:
        return lecteur().strip()
    except OSError:
        return ""


def urls(nom: Optional[str] = None, ips: Optional[List[str]] = None) -> Tuple[Optional[str], List[str]]:
    """(URL par le nom, URLs par IPv4)."""
    nom = nom_hote() if nom is None else nom
    ips = ipv4_utiles() if ips is None else ips
    return (f"https://{nom}{CHEMIN}" if nom else None), [f"https://{i}{CHEMIN}" for i in ips]


def lignes(nom: Optional[str] = None, ips: Optional[List[str]] = None, max_ip: int = 2) -> List[str]:
    """Lignes d'écran : titre, URL du nom, puis « ou » + IP (au plus `max_ip`, le surplus résumé)."""
    u_nom, u_ips = urls(nom, ips)
    out = ["Continuer dans un navigateur :"]
    if u_nom:
        out.append(u_nom)
    vues, reste = u_ips[:max_ip], len(u_ips) - max_ip
    for k, u in enumerate(vues):
        suite = f" (+{reste} autres)" if reste > 0 and k == len(vues) - 1 else ""
        out.append(("ou " if (u_nom or k) else "") + u + suite)
    if not u_nom and not u_ips:
        out.append("(pas d'adresse réseau pour l'instant)")
    return out
