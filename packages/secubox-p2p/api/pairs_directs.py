# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Liens WireGuard directs entre pairs (#3133).

Le maître (étoile wg-mesh) publie la liste de ses pairs vivants ; chaque pair s'y connecte en direct.
Tout ce qui vient de wg_mesh.json est une donnée écrite par les flux d'enrôlement : on la valide strictement
(re.fullmatch, jamais un `$` nu) et une entrée mal typée est écartée, jamais une exception."""
import copy
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
    """Enveloppe pour la route (horloge réelle). La route répond 503 sans mesure ; None reste sûr ici : personne."""
    return liste_publiable(etat, poignees or {}, time.time())


# --- côté pair : calcul des liens directs (logique pure : ni fichier, ni réseau, ni horloge) ------------------------

def _ips_reservees(etat: dict) -> set:
    """IP jamais attribuables à un lien direct : la première adresse hôte du réseau (le maître, même si son entrée
    n'a pas de mesh_ip : un /32 l'emporterait sur son /24), l'adresse réseau, la diffusion et la nôtre."""
    net = ipaddress.ip_network(RESEAU_MAILLE)
    res = {str(net.network_address), str(net.network_address + 1), str(net.broadcast_address)}
    adresse = etat.get("address")
    if isinstance(adresse, str):
        ip = _ipv4(adresse.split("/")[0].strip())
        if ip is not None:
            res.add(str(ip))
    return res


SONDE, ACTIF = "sonde", "actif"


def etat_direct(e: Any) -> str:
    """« actif » seulement si l'entrée le dit explicitement ; tout le reste (absent, inconnu, mal typé) est une sonde,
    qui ne prend aucun trafic : en cas de doute, le trafic reste à la route du maître."""
    return ACTIF if isinstance(e, dict) and e.get("direct_etat") == ACTIF else SONDE


def calculer(etat: Any, liste: Any, poignees: Any, maintenant: float, delai_poignee_s: int = 180) -> Dict[str, Any]:
    """Décide des liens directs : « sonde puis promotion ».

    - ajouts : pair listé par le maître et inconnu ici -> nouvelle SONDE (clé + endpoint, sans AllowedIPs : elle ne
      prend aucun trafic au maître ; ses keepalives provoquent la poignée de main si l'autre pair a aussi notre clé) ;
    - promotions : sonde dont une poignée de main a moins de delai_poignee_s -> ACTIF (AllowedIPs = <ip>/32) ;
    - retrogradations : actif sans poignée depuis plus de delai_poignee_s ET promu depuis plus de delai_poignee_s
      -> SONDE (le /32 disparaît, le trafic revient au maître) ;
    - retraits : entrée directe dont le maître ne liste plus le pair (seul cas de suppression).

    Rend {"ajouts": [pair normalisé…], "promotions": [clé…], "retrogradations": [clé…], "retraits": [clé…]}.
    Toute entrée mal typée est écartée en silence, jamais une exception."""
    vide: Dict[str, Any] = {"ajouts": [], "promotions": [], "retrogradations": [], "retraits": []}
    if not isinstance(etat, dict) or isinstance(maintenant, bool) or _horodatage(maintenant) is None:
        return vide
    poignees = poignees if isinstance(poignees, dict) else {}
    entrees = etat.get("peers")
    entrees = [e for e in entrees if isinstance(e, dict)] if isinstance(entrees, list) else []
    moi = etat.get("public_key")
    cles_fixes, ips_prises = set(), set()           # entrées NON directes (maître compris) : jamais en double
    ips_prises.update(_ips_reservees(etat))
    directs: Dict[str, dict] = {}
    for e in entrees:
        cle = e.get("public_key")
        if e.get("direct") is True:
            if isinstance(cle, str):
                directs[cle] = e
            continue
        if isinstance(cle, str):
            cles_fixes.add(cle)
        for champ in ("mesh_ip", "allowed_ips"):
            v = e.get(champ)
            if isinstance(v, str):
                ips_prises.add(v.split("/")[0].strip())
    for e in directs.values():
        if isinstance(e.get("mesh_ip"), str):
            ips_prises.add(e["mesh_ip"])
    valides: Dict[str, Dict[str, str]] = {}
    for brut in liste if isinstance(liste, list) else []:
        p = valider_pair(brut)
        if p is None or p["cle_publique"] == moi or p["cle_publique"] in cles_fixes:
            continue
        ai = brut.get("allowed_ips")
        if isinstance(ai, str) and not ai.strip().endswith("/32"):
            continue                                # le maître (/24) ou toute route large
        valides.setdefault(p["cle_publique"], p)    # doublon de clé : la première entrée
    retraits: List[str] = []
    promotions: List[str] = []
    retrogradations: List[str] = []
    for cle, e in directs.items():
        if cle not in valides:
            retraits.append(cle)
            continue
        ts = _horodatage(poignees.get(cle))
        recente = ts is not None and 0 <= maintenant - ts < delai_poignee_s
        if etat_direct(e) == SONDE:
            if recente:
                promotions.append(cle)
            continue
        depuis = _horodatage(e.get("direct_depuis"))
        # promu depuis plus du délai ; un horodatage absent, invalide ou futur ne protège pas le /32 (côté sûr)
        ancien = depuis is None or not 0 <= maintenant - depuis <= delai_poignee_s
        if not recente and ancien:
            retrogradations.append(cle)
    ajouts: List[Dict[str, str]] = []
    ips_ajoutees = set()
    places = MAX_PAIRS - len(directs)
    for cle, p in sorted(valides.items(), key=lambda kv: int(ipaddress.IPv4Address(kv[1]["mesh_ip"]))):
        if cle in directs or p["mesh_ip"] in ips_prises or p["mesh_ip"] in ips_ajoutees:
            continue
        if len(ajouts) >= places:
            break
        ips_ajoutees.add(p["mesh_ip"])
        ajouts.append(p)
    return {"ajouts": ajouts, "promotions": promotions, "retrogradations": retrogradations, "retraits": retraits}


def _cles(calcul: dict, champ: str) -> set:
    v = calcul.get(champ)
    return {c for c in v if isinstance(c, str)} if isinstance(v, list) else set()


def appliquer(etat: Any, calcul: Any, maintenant: float) -> dict:
    """Nouvel état = copie de l'ancien, retraits, rétrogradations, promotions puis ajouts. Seules les entrées
    « direct » sont touchées. Les ajouts sont REVALIDÉS (valider_pair) puis reconstruits champ par champ, en sonde
    (aucune AllowedIPs) ; une promotion revérifie l'IP (réseau maillé, ni réservée ni tenue par une autre entrée)."""
    if not isinstance(etat, dict):
        return {}
    nouveau = copy.deepcopy(etat)
    if not isinstance(nouveau.get("peers"), list) or not isinstance(calcul, dict):
        return nouveau
    retraits, promotions = _cles(calcul, "retraits"), _cles(calcul, "promotions")
    retrogradations = _cles(calcul, "retrogradations")
    pairs = [e for e in nouveau["peers"] if not (isinstance(e, dict) and e.get("direct") is True
                                                  and e.get("public_key") in retraits)]
    net = ipaddress.ip_network(RESEAU_MAILLE)
    reservees = _ips_reservees(nouveau)
    for e in pairs:
        if not (isinstance(e, dict) and e.get("direct") is True):
            continue
        cle = e.get("public_key")
        if cle in retrogradations and etat_direct(e) == ACTIF:
            e["direct_etat"] = SONDE
            e.pop("allowed_ips", None)
            e["direct_depuis"] = int(maintenant)
        elif cle in promotions and etat_direct(e) == SONDE:
            ip = _ipv4(e.get("mesh_ip"))
            autres = set()
            for x in pairs:
                if x is e or not isinstance(x, dict):
                    continue
                for champ in ("mesh_ip", "allowed_ips"):
                    if isinstance(x.get(champ), str):
                        autres.add(x[champ].split("/")[0].strip())
            if ip is None or ip not in net or str(ip) in reservees or str(ip) in autres:
                continue
            e["direct_etat"] = ACTIF
            e["allowed_ips"] = f"{ip}/32"
            e["direct_depuis"] = int(maintenant)
    cles = {e.get("public_key") for e in pairs if isinstance(e, dict)}
    ips = {e.get("mesh_ip") for e in pairs if isinstance(e, dict)} | reservees
    for a in calcul.get("ajouts") if isinstance(calcul.get("ajouts"), list) else []:
        if not isinstance(a, dict):
            continue
        p = valider_pair({"name": a.get("nom"), "public_key": a.get("cle_publique"),
                          "mesh_ip": a.get("mesh_ip"), "endpoint": a.get("endpoint")})
        if p is None or p["cle_publique"] in cles or p["mesh_ip"] in ips:
            continue
        cles.add(p["cle_publique"])
        ips.add(p["mesh_ip"])
        pairs.append({"public_key": p["cle_publique"], "mesh_ip": p["mesh_ip"], "name": p["nom"],
                      "endpoint": p["endpoint"], "direct": True, "direct_etat": SONDE,
                      "direct_depuis": int(maintenant)})
    nouveau["peers"] = pairs
    return nouveau


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
