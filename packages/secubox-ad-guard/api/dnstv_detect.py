# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: détection des candidats du mode « auto » (#1954).

Heuristique issue d'UN cas réel (replay France TV, TV Android, 2026-10-03) : une coupure publicitaire commence par une requête vers un
serveur d'insertion (FreeWheel) ; les noms demandés dans les secondes qui suivent et jamais en lecture normale sont ceux de la pub.
Elle n'est pas validée ailleurs : tout candidat passe par l'essai et la confirmation de l'administrateur.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, List, Set

try:
    from . import dnstv
except ImportError:
    from api import dnstv

# Domaines génériques : les bloquer casserait le système de l'appareil ou d'autres services. Jamais proposés (suffixe compris).
LISTE_NOIRE = ("googleapis.com", "gstatic.com", "google.com", "googleusercontent.com", "apple.com", "icloud.com", "aaplimg.com",
               "amazonaws.com", "cloudfront.net", "cloudflare.com", "akamaiedge.net", "akamaized.net", "akadns.net",
               "microsoft.com", "windowsupdate.com", "ntp.org", "arpa", "local", "lan", "home", "invalid")
CLASSES_PUB = ("advertising", "tracking")
SCORE_CLASSE = 70
SCORE_INCONNU = 30
BONUS_COUPURE = 10          # par coupure supplémentaire (plafonné) — valeurs de départ, à calibrer sur plusieurs jours réels


@dataclass
class Candidat:
    domaine: str
    score: int
    risque: str
    coupures: int
    motif: str


def est_liste_noire(domaine: str) -> bool:
    return any(domaine == s or domaine.endswith("." + s) for s in LISTE_NOIRE)


def _coupures(evts: List[dict], est_declencheur: Callable[[str], bool], fenetre_s: int, pause_s: int) -> List[tuple]:
    """Fenêtres [début, fin] : une coupure commence à un déclencheur non précédé d'un autre dans les `pause_s` secondes."""
    debuts, dernier = [], None
    for e in evts:
        if est_declencheur(e["domaine"]):
            if dernier is None or e["ts"] - dernier > pause_s:
                debuts.append(e["ts"])
            dernier = e["ts"]
    return [(d, d + fenetre_s) for d in debuts]


def detecter(evts: List[dict], est_declencheur: Callable[[str], bool], classer: Callable[[str], str], exclus: Set[str],
             fenetre_s: int = 60, pause_s: int = 120, min_coupures: int = 2, min_variantes: int = 3) -> List[Candidat]:
    evts = [e for e in evts if e.get("decision") != "BLOCKED" and dnstv.valider_domaine(e.get("domaine", "")) == e.get("domaine")]
    fenetres = _coupures(evts, est_declencheur, fenetre_s, pause_s)
    if not fenetres:
        return []
    dans: Dict[str, Set[int]] = defaultdict(set)      # domaine → coupures où il apparaît
    hors: Set[str] = set()
    for e in evts:
        k = next((i for i, (a, b) in enumerate(fenetres) if a <= e["ts"] <= b), None)
        if k is None:
            hors.add(e["domaine"])
        else:
            dans[e["domaine"]].add(k)
    bruts: Dict[str, Candidat] = {}
    for d, ks in dans.items():
        if d in exclus or est_liste_noire(d):
            continue
        classe = classer(d) in CLASSES_PUB
        n = len(ks)
        if classe:
            risque = "partage" if d in hors else "faible"
            score, motif = SCORE_CLASSE + min(20, BONUS_COUPURE * (n - 1)), f"classé {classer(d)} par les listes, vu dans {n} coupure(s)"
        elif d not in hors and n >= min_coupures:
            risque, score, motif = "faible", SCORE_INCONNU + min(30, BONUS_COUPURE * (n - min_coupures)), f"vu seulement pendant {n} coupures"
        else:
            continue
        bruts[d] = Candidat(d, score, risque, n, motif)
    # regroupement des noms à partie variable sous leur parent (≥ 3 variantes, parent de ≥ 3 libellés, hors liste noire)
    parents: Dict[str, List[str]] = defaultdict(list)
    for d in bruts:
        p = d.split(".", 1)[1] if "." in d else ""
        if p.count(".") >= 1 and p not in exclus and not est_liste_noire(p):
            parents[p].append(d)
    for p, enfants in parents.items():
        sous_arbre_vu_hors = any(h == p or h.endswith("." + p) for h in hors)
        if len(enfants) >= min_variantes and p.count(".") >= 2 and not sous_arbre_vu_hors:
            tete = max(bruts[e].score for e in enfants)
            n = max(bruts[e].coupures for e in enfants)
            for e in enfants:
                del bruts[e]
            bruts[p] = Candidat(p, tete, "variable", n, f"{len(enfants)} noms à partie variable regroupés")
    return sorted(bruts.values(), key=lambda c: (-c.score, c.domaine))
