# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Table de voisinage (`ip -j neigh`) : adresse MAC → adresses IP globales, comme le fait ad-guard pour regrouper IPv4 et IPv6 d'un appareil."""
import ipaddress
import json
import re
import subprocess
import sys

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def lire(texte) -> dict:
    """{mac: [adresses]} ; entrées échouées, lien-local, multicast, bouclage et valeurs invalides ignorées. Jamais d'exception."""
    try:
        brut = json.loads(texte)
    except (ValueError, TypeError):
        return {}
    if not isinstance(brut, list):
        return {}
    sortie: dict = {}
    for e in brut:
        if not isinstance(e, dict):
            continue
        dst, ll, etat = e.get("dst"), e.get("lladdr"), e.get("state") or []
        if not isinstance(dst, str) or not isinstance(ll, str) or "%" in dst:
            continue
        if any(s in ("FAILED", "INCOMPLETE") for s in etat if isinstance(s, str)):
            continue
        mac = ll.lower()
        if not _MAC.match(mac) or int(mac[:2], 16) & 1:                  # adresse MAC valide et unicast
            continue
        try:
            a = ipaddress.ip_address(dst)
        except ValueError:
            continue
        if a.is_link_local or a.is_multicast or a.is_loopback or a.is_unspecified:
            continue
        liste = sortie.setdefault(mac, [])
        if str(a) not in liste:
            liste.append(str(a))
    return sortie


def depuis_systeme() -> dict:
    try:
        r = subprocess.run(["/usr/sbin/ip", "-j", "neigh"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"secubox-webfilter : table de voisinage illisible : {e}", file=sys.stderr)
        return {}
    return lire(r.stdout)
