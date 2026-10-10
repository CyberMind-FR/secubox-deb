# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Vue d'ensemble de l'administration (#2212) : agrège des caches déjà en mémoire.

Fonction pure : aucune E/S, aucun sous-processus (jamais `check_updates` ni `systemctl`),
donc sans risque pour la boucle partagée de l'agrégateur. Une donnée absente reste `None`,
elle n'est jamais inventée ni remplacée par un zéro rassurant.
"""
from typing import Optional

SEUIL_CRITIQUE = 95.0   # % disque / mémoire / CPU au-delà duquel la box est dite critique
MAX_ALERTES = 5
_GRAVITE = {"inconnu": 0, "ok": 1, "degrade": 2, "critique": 3}


def _arrondi(v) -> Optional[float]:
    return round(float(v), 1) if isinstance(v, (int, float)) else None


def _espace(e: dict) -> dict:
    items = [i for i in e.get("items") or [] if i.get("installed", True)]
    arretes = [i.get("id") for i in items if not i.get("active")]
    return {"id": e.get("id"), "nom": e.get("nom"), "icone": e.get("icone"), "total": len(items),
            "actifs": len(items) - len(arretes), "arretes": arretes,
            "etat": "degrade" if arretes else "ok"}


def construire_apercu(menu: Optional[dict], stats: Optional[dict], notifications, uptime) -> dict:
    menu, stats = menu or {}, stats or {}
    espaces = [_espace(e) for e in menu.get("espaces") or []]
    ressources = {"cpu": _arrondi(stats.get("cpu_percent")), "memoire": _arrondi(stats.get("memory_percent")),
                  "disque": _arrondi(stats.get("disk_percent")), "charge": stats.get("load_avg")}
    notifs = notifications if isinstance(notifications, list) else []
    etat = "inconnu"
    if espaces:
        etat = max((e["etat"] for e in espaces), key=_GRAVITE.get)
        if any(v is not None and v >= SEUIL_CRITIQUE for v in (ressources["cpu"], ressources["memoire"], ressources["disque"])):
            etat = "critique"
    return {"etat": etat, "uptime": uptime, "espaces": espaces, "ressources": ressources,
            "alertes": {"total": len(notifs), "recentes": notifs[:MAX_ALERTES]}}
