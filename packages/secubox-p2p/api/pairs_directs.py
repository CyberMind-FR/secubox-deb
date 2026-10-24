# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Liens WireGuard directs entre pairs (#3133).

Le maître (étoile wg-mesh) publie la liste de ses pairs vivants ; chaque pair s'y connecte en direct.
Tout ce qui vient de wg_mesh.json est une donnée écrite par les flux d'enrôlement : on la valide strictement
(re.fullmatch, jamais un `$` nu) et une entrée mal typée est écartée, jamais une exception."""
import ipaddress
import math
import re
import time
from typing import Any, Dict, List, Optional

from . import mesh

RESEAU_MAILLE = "10.10.0.0/24"
MAX_PAIRS = 32
AGE_MAX_S = 600

_NOM = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
_ENDPOINT = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
_PRIVES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _ipv4(valeur: Any) -> Optional[ipaddress.IPv4Address]:
    if not isinstance(valeur, str) or not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", valeur):
        return None
    try:
        return ipaddress.IPv4Address(valeur)
    except ValueError:
        return None


def valider_pair(p: Any, reseau: str = RESEAU_MAILLE) -> Optional[Dict[str, str]]:
    """Pair normalisé {nom, mesh_ip, cle_publique, endpoint}, ou None si une seule valeur est douteuse."""
    if not isinstance(p, dict):
        return None
    net = ipaddress.ip_network(reseau)
    nom, cle, ep = p.get("name"), p.get("public_key"), p.get("endpoint")
    if not isinstance(nom, str) or not _NOM.fullmatch(nom):
        return None
    if not mesh.valid_wg_key(cle):
        return None
    ip = _ipv4(p.get("mesh_ip"))
    if ip is None or ip not in net or ip == net.network_address or ip == net.broadcast_address:
        return None
    if not isinstance(ep, str):
        return None
    m = _ENDPOINT.fullmatch(ep)
    if not m:
        return None
    hote, port = _ipv4(m.group(1)), int(m.group(2))
    if hote is None or not 1 <= port <= 65535:
        return None
    if hote in net or not any(hote in r for r in _PRIVES):
        return None
    return {"nom": nom, "mesh_ip": str(ip), "cle_publique": cle, "endpoint": f"{hote}:{port}"}


def _horodatage(valeur: Any) -> Optional[float]:
    if isinstance(valeur, bool) or not isinstance(valeur, (int, float)) or not math.isfinite(valeur):
        return None
    return float(valeur)


def liste_publiable(etat: dict, poignees: dict, maintenant: float, age_max_s: int = AGE_MAX_S) -> List[Dict[str, str]]:
    """Les pairs vivants (poignée de main de moins de age_max_s), dédoublonnés par clé, triés par IP, au plus 32."""
    if not isinstance(etat, dict) or not isinstance(poignees, dict):
        return []
    pairs = etat.get("peers")
    if not isinstance(pairs, list):
        return []
    retenus: Dict[str, Dict[str, str]] = {}
    for brut in pairs:
        p = valider_pair(brut)
        if p is None or not str(brut.get("allowed_ips", "")).endswith("/32"):
            continue
        ts = _horodatage(poignees.get(p["cle_publique"]))
        if ts is None or not 0 <= maintenant - ts < age_max_s:
            continue
        retenus.setdefault(p["cle_publique"], p)
    liste = sorted(retenus.values(), key=lambda q: int(ipaddress.IPv4Address(q["mesh_ip"])))
    return liste[:MAX_PAIRS]


def pairs_vivants(etat: dict, poignees: Optional[dict]) -> List[Dict[str, str]]:
    """Enveloppe pour la route : sans mesure de poignées, personne n'est publié."""
    return liste_publiable(etat, poignees or {}, time.time())
