# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Règles de répartition de MirrorNet v1 (#3645, docs/MIRRORNET_ECONOMY.md § 4).

Une règle est VERSIONNÉE et jamais en dur : parts entières en pourcentage, de somme 100, parmi quatre rôles.
`repartir` découpe un montant entier en parts entières dont la somme vaut EXACTEMENT le montant (plus forts restes,
départage déterministe dans l'ordre des rôles) : aucun centième n'est créé ni perdu.
"""
from __future__ import annotations

from typing import Dict, Mapping

ROLES = ("producteur", "relais", "infrastructure", "reserve")


class RegleInvalide(ValueError):
    pass


def valider(parts: Mapping[str, int], sans_relais: str = "producteur") -> Dict[str, int]:
    if not isinstance(parts, Mapping) or not parts:
        raise RegleInvalide("parts manquantes")
    inconnus = set(parts) - set(ROLES)
    if inconnus:
        raise RegleInvalide(f"rôles inconnus : {sorted(inconnus)}")
    for r, p in parts.items():
        if type(p) is not int or not 0 <= p <= 100:
            raise RegleInvalide(f"part de {r} : entier entre 0 et 100 exigé")
    if sum(parts.values()) != 100:
        raise RegleInvalide("la somme des parts doit valoir 100")
    if sans_relais not in ROLES or sans_relais == "relais":
        raise RegleInvalide("sans_relais : rôle qui reçoit la part du relais absent (pas « relais »)")
    return {r: int(parts.get(r, 0)) for r in ROLES}


def repartir(montant: int, parts: Mapping[str, int], *, avec_relais: bool = True,
             sans_relais: str = "producteur") -> Dict[str, int]:
    """Découpe `montant` (entier ≥ 0, centièmes) selon `parts` ; sans relais, sa part va à `sans_relais`."""
    if type(montant) is not int or montant < 0:
        raise RegleInvalide("montant entier positif ou nul exigé")
    p = valider(parts, sans_relais)
    if not avec_relais:
        p[sans_relais] += p["relais"]
        p["relais"] = 0
    bruts = {r: montant * p[r] for r in ROLES}                 # en centièmes × 100
    res = {r: bruts[r] // 100 for r in ROLES}
    reste = montant - sum(res.values())
    ordre = sorted(ROLES, key=lambda r: (-(bruts[r] % 100), ROLES.index(r)))
    for r in ordre[:reste]:
        res[r] += 1
    return res
