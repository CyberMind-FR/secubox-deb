# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Politique de décision de secubox-garde (#3794) : pure, sans fichier, réseau, base ni horloge.

Tout arrive par paramètres ; le moteur attribue les identifiants et persiste les décisions.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

BAN_BASE = 14400          # 4 h
BAN_PLAFOND = 2592000     # 30 j
QUARANTAINE = 86400       # 24 h
FENETRE_INFECTION = 3600
FAMILLES = frozenset({"dga", "exfiltration", "malicious"})
MAILLAGE = ipaddress.ip_network("10.100.0.0/16")
MSG_MASSE = "comportement de masse anormal : quarantaines au plafond, appareils non isolés"


@dataclass
class Signal:
    source: str
    type: str
    ip: str
    mac: Optional[str]
    domaine: str
    regle: str
    ts: int


@dataclass
class Decision:
    menace: str
    cible: str
    mac: Optional[str]
    ip: str
    motif: str
    signe: str
    debut: int
    fin: int


def _bannissable(ip: str) -> bool:
    """Adresse publique routable, hors maillage ; toute adresse illisible est refusée."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 4 and a in MAILLAGE:
        return False
    return bool(a.is_global) and not (a.is_private or a.is_loopback or a.is_link_local
                                      or a.is_multicast or a.is_unspecified or a.is_reserved)


def _maillage(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a in MAILLAGE


def _prefixes(reglages: dict) -> list:
    out = []
    for p in reglages.get("lan_prefixes") or []:
        try:
            out.append(ipaddress.ip_network(str(p), strict=False))
        except ValueError:
            continue
    return out


def _lan(ip: str, prefixes: list) -> bool:
    """Adresse du réseau local : privée (ULA, lien-local compris) ou dans un préfixe du LAN."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if _maillage(ip) or a.is_loopback or a.is_multicast or a.is_unspecified:
        return False
    return bool(a.is_private) or any(a.version == n.version and a in n for n in prefixes)


def _actif(actives: List[Decision], menace: str, cible: str, maintenant: int) -> bool:
    return any(d.menace == menace and d.cible == cible and d.fin > maintenant for d in actives)


def _fenetre(sigs: List[Signal]) -> set:
    """Plus grand ensemble de familles vues dans une même fenêtre d'une heure."""
    pris = sorted((s for s in sigs if s.type in FAMILLES), key=lambda s: s.ts)
    meilleur: set = set()
    for i, s in enumerate(pris):
        types = {p.type for p in pris[i:] if p.ts - s.ts <= FENETRE_INFECTION}
        if len(types) > len(meilleur):
            meilleur = types
    return meilleur


def decider(signaux: List[Signal], actives: List[Decision],
            liberations: Dict[Tuple[str, str], int], recidives: Dict[str, int],
            protegees: Callable[[str], bool], reglages: dict,
            maintenant: int) -> Tuple[List[Decision], List[str]]:
    auto = reglages.get("automatique", True) is not False
    plafond = int(reglages.get("quarantaines_max", 3))
    nouvelles: List[Decision] = []
    alertes: List[str] = []

    # -- intrusions : bans d'adresses publiques
    par_ip: Dict[str, List[Signal]] = {}
    for s in signaux:
        if s.type == "intrusion":
            par_ip.setdefault(s.ip, []).append(s)
    for ip, ss in par_ip.items():
        if not _bannissable(ip) or protegees(ip) or _actif(actives, "intrusion", ip, maintenant):
            continue
        n = max(0, int(recidives.get(ip, 0)))
        duree = min(BAN_BASE * 4 ** min(n, 20), BAN_PLAFOND)
        regles = "+".join(sorted({s.regle for s in ss if s.regle})) or "intrusion"
        nouvelles.append(Decision("intrusion", ip, None, ip, f"intrusion : {regles}", "intrusion",
                                  maintenant, maintenant + duree))

    # -- appareils du réseau local, regroupés par MAC (à défaut IP)
    par_appareil: Dict[str, List[Signal]] = {}
    for s in signaux:
        if s.type != "intrusion":
            par_appareil.setdefault(s.mac or s.ip, []).append(s)
    actives_infection = sum(1 for d in actives if d.menace == "infection" and d.fin > maintenant)
    masse = False
    prefixes = _prefixes(reglages)
    for cle, ss in par_appareil.items():
        if any(_maillage(s.ip) or protegees(s.ip) for s in ss):
            continue
        ss = [s for s in ss if _lan(s.ip, prefixes)]
        if not ss:
            continue
        ref = ss[0]
        mac, ip = ref.mac, ref.ip
        agi = False
        evas = sorted({s.type for s in ss if s.type in ("doh", "tunneling")})
        if evas and not _actif(actives, "evasion", cle, maintenant):
            signe = evas[0]
            nouvelles.append(Decision("evasion", cle, mac, ip, f"évasion : {', '.join(evas)}",
                                      signe, maintenant, maintenant + QUARANTAINE))
            agi = True
        elif evas:
            agi = True
        types = _fenetre(ss)
        if types and ("malicious" in types or len(types) >= 2):
            signe = "+".join(sorted(types))
            agi = True
            libere = any(jusqua > maintenant and set(sg.split("+")) & types
                         for (k, sg), jusqua in liberations.items() if k == cle)
            if not libere and not _actif(actives, "infection", cle, maintenant):
                if auto and actives_infection >= plafond:
                    masse = True
                else:
                    if auto:
                        actives_infection += 1
                    nouvelles.append(Decision("infection", cle, mac, ip, f"infection : {signe}",
                                              signe, maintenant, maintenant + QUARANTAINE))
        if not agi:
            for t in sorted({s.type for s in ss if s.type in ("dga", "high_rate", "exfiltration")}):
                nouvelles.append(Decision("signale", cle, mac, ip, f"{t} : signe isolé", t,
                                          maintenant, maintenant))
    if masse:
        alertes.append(MSG_MASSE)

    if not auto:
        nouvelles = [Decision("signale", d.cible, d.mac, d.ip, d.motif, d.signe,
                              d.debut, d.debut) for d in nouvelles]
    return nouvelles, alertes
