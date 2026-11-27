# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Bibliothèque figée de motifs (#4020) : `GET /bibliotheque`, vue par famille de la page WAF › Modes.

Lecture seule. Assemble, par famille `bib_<famille>` :
- le rapport de construction livré (`/usr/share/secubox/waf/bibliotheque/rapport.json`) : règles importées,
  converties, rejetées au rejeu, touches rejouées sur l'échantillon réel ;
- le mode en vigueur sur la box (`modes.lire_categories`, donc `secubox-cvectl waf-modes lister`) ;
- les touches sur 7 jours, sommées depuis le cache `stats7j` (étiquettes `bib:<famille>:<techno>`).

L'ÉCRITURE n'a pas de route propre : la page envoie ses choix à `POST /categories/modes` (#3741), la voie
existante (ctl confiné, double tampon, audit). « Identifier seulement » = mode detect ; « bannir » = escalate ou
block, choisi par famille.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends
from secubox_core.auth import require_lecture

log = logging.getLogger("secubox.waf.bibliotheque")

router = APIRouter()

RAPPORT = Path("/usr/share/secubox/waf/bibliotheque/rapport.json")
PREFIXE_CAT = "bib_"
PREFIXE_ETIQUETTE = "bib:"

#: Branchements de main.py (par défaut, ceux de modes.py).
_config: Dict[str, Callable[..., Any]] = {}


def configurer(*, categories: Callable[[], dict], stats7j: Callable[[], dict],
               rapport: Optional[Path] = None) -> None:
    _config.update(categories=categories, stats7j=stats7j)
    if rapport is not None:
        _config["rapport"] = rapport


def _rapport() -> dict:
    try:
        data = json.loads(Path(_config.get("rapport") or RAPPORT).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as e:
        log.warning("bibliothèque : rapport livré illisible : %s", e)
        return {}


def touches_par_famille(stats: dict) -> Optional[Dict[str, dict]]:
    """Touches 7 j par famille, depuis les étiquettes bib:<famille>:<techno> ; None si le relevé manque."""
    cats = (stats or {}).get("categories")
    if not isinstance(cats, dict):
        return None
    out: Dict[str, dict] = {}
    for cle, v in cats.items():
        if not isinstance(cle, str) or not cle.startswith(PREFIXE_ETIQUETTE) or not isinstance(v, dict):
            continue
        parts = cle.split(":", 2)
        fam = parts[1] if len(parts) > 1 and parts[1] else "autre"
        techno = parts[2] if len(parts) > 2 and parts[2] else "generique"
        f = out.setdefault(fam, {"touches": 0, "par_jour": [0] * 7, "technos": {}})
        n = int(v.get("touches") or 0)
        f["touches"] += n
        f["technos"][techno] = f["technos"].get(techno, 0) + n
        pj = v.get("par_jour")
        if isinstance(pj, list) and len(pj) == 7:
            f["par_jour"] = [a + int(b or 0) for a, b in zip(f["par_jour"], pj)]
    for f in out.values():
        f["technos"] = dict(sorted(f["technos"].items(), key=lambda kv: -kv[1])[:8])
    return out


def lire_bibliotheque() -> dict:
    rap = _rapport()
    cats = (_config["categories"]() or {})
    source = cats.get("source")
    cats = cats.get("categories") or {}
    live = touches_par_famille(_config["stats7j"]())
    familles = {}
    for fam, d in sorted((rap.get("familles") or {}).items()):
        if not isinstance(d, dict) or not d.get("retenues"):
            continue
        cat = cats.get(PREFIXE_CAT + fam) or {}
        mode = cat.get("mode") if cat else None
        familles[fam] = {
            "categorie": PREFIXE_CAT + fam,
            "name": cat.get("name") or fam,
            "presente": bool(cat),
            "mode": mode,
            "ban_seuil": cat.get("ban_seuil"),
            "ban_duree": cat.get("ban_duree"),
            "identifier_seulement": mode in (None, "detect"),
            "regles": int(d.get("retenues") or 0),
            "regex": int(d.get("regex") or 0),
            "chemins_exacts": int(d.get("chemins_exacts") or 0),
            "importees": int(d.get("importees") or 0),
            "rejetees_rejeu": int(d.get("rejetees_rejeu") or 0),
            "touches_rejouees": int(d.get("touches_rejouees") or 0),
            "touches_7j": (live or {}).get(fam) if live is not None else None,
        }
    return {"familles": familles, "sources": rap.get("sources") or {}, "rejeu": rap.get("rejeu") or {},
            "total_regles": sum(f["regles"] for f in familles.values()), "source_modes": source}


@router.get("/bibliotheque", dependencies=[Depends(require_lecture)])
async def bibliotheque():
    """Familles de la bibliothèque : règles, touches rejouées et sur 7 jours, mode en vigueur."""
    return await asyncio.to_thread(lire_bibliotheque)
