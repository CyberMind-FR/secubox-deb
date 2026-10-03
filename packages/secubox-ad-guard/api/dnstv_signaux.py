# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: signaux de casse du mode « auto » (#1954).

Le DNS ne voit pas l'écran : ces signaux sont INDIRECTS et leurs seuils sont des valeurs de départ, à calibrer sur plusieurs jours réels.
Étalon mesuré (2026-10-03, TV Android, lecture France TV NORMALE) : un domaine refusé est redemandé ~10 fois par minute (20 à 24 en 2,5 min).
Le seuil de rafale est donc nettement au-dessus : un seuil proche de ce comportement retirerait des règles qui fonctionnent.
"""
from __future__ import annotations

from typing import Dict, List, Set

SEUIL_REFUS_MIN = 60          # refus/minute vers un même domaine (≈ 6× l'étalon mesuré) — à calibrer
DUREE_RAFALE_MIN = 5          # minutes consécutives
MIN_REQUETES_ACTIF = 100      # requêtes depuis la règle pour considérer l'appareil « actif » — à calibrer
DUREE_MIN_S = 1800            # pas de jugement « contenu disparu » avant 30 min d'essai — à calibrer
MIN_JOURS_CONTENU = 3         # un domaine de contenu : vu au moins 3 jours distincts avant la règle


def rafale(evts: List[dict], domaines: Set[str], maintenant: int, seuil_par_min: int = SEUIL_REFUS_MIN, minutes: int = DUREE_RAFALE_MIN) -> List[str]:
    """Domaines gérés par une règle dont les refus dépassent `seuil_par_min` pendant chacune des `minutes` dernières minutes."""
    par: Dict[str, Dict[int, int]] = {}
    for e in evts:
        if e.get("decision") == "BLOCKED" and e.get("domaine") in domaines:
            m = (maintenant - e["ts"]) // 60
            if 0 <= m < minutes:
                par.setdefault(e["domaine"], {}).setdefault(m, 0)
                par[e["domaine"]][m] += 1
    return sorted(d for d, ms in par.items() if len(ms) == minutes and all(n > seuil_par_min for n in ms.values()))


def contenu_disparu(jours_vus: Dict[str, int], vus_depuis: Set[str], requetes_depuis: int,
                    min_jours: int = MIN_JOURS_CONTENU, min_requetes: int = MIN_REQUETES_ACTIF) -> List[str]:
    """Domaines de contenu habituels (vus ≥ `min_jours` jours) qui ne sont plus demandés alors que l'appareil reste actif.
    Un appareil inactif (éteint, en veille) ne déclenche jamais rien."""
    if requetes_depuis < min_requetes:
        return []
    return sorted(d for d, n in jours_vus.items() if n >= min_jours and d not in vus_depuis)
