# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Différence entre deux graphes du paysage (#3921). Fonction pure, tolérante : aucun espacement supposé entre les
deux graphes, métriques ou nœuds manquants ou mal typés ignorés (une métrique absente d'un côté n'est pas comparée)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

METRIQUES = ("adresses", "bans", "reseaux")
SEUIL_RELATIF = 0.20
SEUIL_ABSOLU = 10


def _noeuds(g: Any) -> Dict[str, dict]:
    res: Dict[str, dict] = {}
    liste = g.get("noeuds") if isinstance(g, dict) else None
    for n in liste if isinstance(liste, list) else []:
        if isinstance(n, dict) and isinstance(n.get("id"), str):
            res[n["id"]] = n
    return res


def _metrique(n: dict, nom: str) -> Optional[int]:
    m = n.get("metriques")
    v = m.get(nom) if isinstance(m, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _rotation(n: dict) -> Optional[bool]:
    m = n.get("metriques")
    v = m.get("rotation") if isinstance(m, dict) else None
    return v if isinstance(v, bool) else None


def _notable(de: int, a: int) -> bool:
    ecart = abs(a - de)
    return ecart > SEUIL_ABSOLU and ecart > SEUIL_RELATIF * de


def difference(avant: Optional[dict], apres: dict) -> dict:
    """Apparus / disparus (tous nœuds), hausses / baisses notables (écart > 20 % et > 10) des métriques des nœuds
    `population`, rotation levée / tombée (populations présentes des deux côtés). `avant=None` : tout apparaît."""
    a, b = _noeuds(avant), _noeuds(apres)
    hausses: List[dict] = []
    baisses: List[dict] = []
    levee: List[str] = []
    tombee: List[str] = []
    for ident in sorted(a.keys() & b.keys()):
        na, nb = a[ident], b[ident]
        if na.get("type") != "population" or nb.get("type") != "population":
            continue
        for nom in METRIQUES:
            de, vers = _metrique(na, nom), _metrique(nb, nom)
            if de is None or vers is None or not _notable(de, vers):
                continue
            (hausses if vers > de else baisses).append({"id": ident, "metrique": nom, "de": de, "a": vers})
        ra, rb = _rotation(na), _rotation(nb)
        if ra is False and rb is True:
            levee.append(ident)
        elif ra is True and rb is False:
            tombee.append(ident)
    return {"apparus": sorted(b.keys() - a.keys()), "disparus": sorted(a.keys() - b.keys()),
            "hausses": hausses, "baisses": baisses, "rotation_levee": levee, "rotation_tombee": tombee}
