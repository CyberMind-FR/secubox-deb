# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Liens WireGuard directs entre pairs (#3133).

Le maître (étoile wg-mesh) publie la liste de ses pairs vivants ; chaque pair s'y connecte en direct.
Tout ce qui vient de wg_mesh.json est une donnée écrite par les flux d'enrôlement : on la valide strictement
(re.fullmatch, jamais un `$` nu) et une entrée mal typée est écartée, jamais une exception."""
import hmac
import ipaddress
import math
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import mesh

RESEAU_MAILLE = "10.10.0.0/24"
MAX_PAIRS = 32
AGE_MAX_S = 600

_NOM = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
_ENDPOINT = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})")
_PRIVES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _ipv4(valeur: Any) -> Optional[ipaddress.IPv4Address]:
    if not isinstance(valeur, str) or not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", valeur):
        return None
    try:
        return ipaddress.IPv4Address(valeur)
    except ValueError:
        return None


def valider_pair(p: Any, reseau: str = RESEAU_MAILLE) -> Optional[Dict[str, str]]:
    """Pair normalisé {nom, mesh_ip, cle_publique, endpoint}, ou None si une seule valeur est douteuse."""
    if not isinstance(p, dict):
        return None
    try:
        net = ipaddress.ip_network(reseau)
    except ValueError:
        return None
    if net.version != 4:
        return None
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
    """Les pairs vivants (poignée de main de moins de age_max_s), dédoublonnés par clé (la dernière entrée gagne),
    triés par IP, au plus 32. Rôle pair : allowed_ips égal exactement à <mesh_ip>/32."""
    if not isinstance(etat, dict) or not isinstance(poignees, dict):
        return []
    pairs = etat.get("peers")
    if not isinstance(pairs, list):
        return []
    retenus: Dict[str, Dict[str, str]] = {}
    for brut in pairs:
        p = valider_pair(brut)
        if p is None:
            continue
        ai = brut.get("allowed_ips")
        if not isinstance(ai, str) or ai.strip() != p["mesh_ip"] + "/32":
            continue
        ts = _horodatage(poignees.get(p["cle_publique"]))
        if ts is None or not 0 <= maintenant - ts < age_max_s:
            continue
        retenus[p["cle_publique"]] = p     # doublon de clé : la DERNIÈRE entrée (enrôlement le plus récent)
    liste = sorted(retenus.values(), key=lambda q: int(ipaddress.IPv4Address(q["mesh_ip"])))
    return liste[:MAX_PAIRS]


def pairs_vivants(etat: dict, poignees: Optional[dict]) -> List[Dict[str, str]]:
    """Enveloppe pour la route : sans mesure de poignées, personne n'est publié."""
    return liste_publiable(etat, poignees or {}, time.time())


# --- jeton du listener 7331 -----------------------------------------------------------------------------------
JETON_CHEMIN = "/etc/secubox/secrets/p2p/pair.token"
_cache_jeton: Dict[str, Any] = {"chemin": None, "mtime": None, "valeur": ""}


def jeton_pair() -> str:
    """Le jeton secret (fichier, relu si son mtime change). Absent, vide ou illisible : chaîne vide (= refus)."""
    chemin = os.environ.get("SBX_P2P_PAIR_TOKEN") or JETON_CHEMIN
    try:
        mtime = os.stat(chemin).st_mtime_ns
        if _cache_jeton["chemin"] != chemin or _cache_jeton["mtime"] != mtime:
            _cache_jeton.update(chemin=chemin, mtime=mtime, valeur=Path(chemin).read_text().strip())
        return _cache_jeton["valeur"]
    except (OSError, ValueError):       # illisible ou non UTF-8 : pas de jeton
        _cache_jeton.update(chemin=None, mtime=None, valeur="")
        return ""


def en_tete_pair_valide(en_tete: Any) -> bool:
    """Vrai si l'en-tête porte exactement le jeton (comparaison à temps constant). Jamais journalisé."""
    jeton = jeton_pair()
    if not jeton or not isinstance(en_tete, str) or not en_tete:
        return False
    return hmac.compare_digest(en_tete.encode(), jeton.encode())
