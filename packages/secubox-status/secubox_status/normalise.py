# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Normalisation des sources en relevé Status v2.

Règles (spec §2.3) :
  1. un module CRITIQUE indisponible peut rendre l'appliance indisponible ;
  2. un module optionnel indisponible la dégrade seulement ;
  3. une mesure absente ou périmée vaut `unknown`, jamais une panne ni un succès ;
  4. l'état global est le pire des composants CONNUS ; tous inconnus = `unknown`.

Un module se juge sur sa couche API : servi par l'agrégateur, son unité systemd est inactive par construction
(vu sur gk2 : 30 modules « dégradés » pour cette seule raison).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .sources import Lecture

_GRAVITE = {"unknown": -1, "operational": 0, "maintenance": 1, "degraded": 2, "outage": 3}
SEUIL_RESSOURCE = 95.0
_VEILLE = {"sleeping", "asleep", "idle", "veille", "on-demand"}


def pire(etats: List[str]) -> str:
    connus = [e for e in etats if e != "unknown"]
    if not connus:
        return "unknown"
    return max(connus, key=lambda e: _GRAVITE.get(e, -1))


def etat_module(m: Dict[str, Any]) -> Tuple[str, bool]:
    """(état, en veille) d'une entrée de modules.json."""
    couches = m.get("layers") if isinstance(m.get("layers"), dict) else {}
    api = couches.get("api") if isinstance(couches.get("api"), dict) else None
    if api is not None:
        s = str(api.get("status") or "").lower()
        if s == "ok":
            return "operational", False
        if s in _VEILLE or str(api.get("detail") or "").lower() in _VEILLE:
            return "operational", True
        if s in ("down", "error", "fail", "failed"):
            return "outage", False
        if s in ("degraded", "slow"):
            return "degraded", False
    general = str(m.get("overall") or m.get("status") or "").lower()
    return {"ok": "operational", "degraded": "degraded", "down": "outage", "error": "outage"}.get(general, "unknown"), \
        general in _VEILLE


def services(lecture: Lecture) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """(état des services, compteurs, détail par module)."""
    vide = {"modules_total": None, "modules_ok": None, "modules_sleeping": None,
            "modules_degraded": None, "modules_down": None}
    if lecture.etat != "fresh" or not isinstance((lecture.donnees or {}).get("modules"), dict):
        return "unknown", vide, []
    detail, critiques_hs = [], False
    for nom, m in sorted(lecture.donnees["modules"].items()):
        if not isinstance(m, dict) or not isinstance(nom, str):
            continue
        etat, veille = etat_module(m)
        critique = m.get("critical") is True
        critiques_hs |= critique and etat == "outage"
        detail.append({"id": nom[:64], "status": etat, "sleeping": veille, "critical": critique})
    c = {
        "modules_total": len(detail),
        "modules_ok": sum(1 for d in detail if d["status"] == "operational" and not d["sleeping"]),
        "modules_sleeping": sum(1 for d in detail if d["sleeping"]),
        "modules_degraded": sum(1 for d in detail if d["status"] == "degraded"),
        "modules_down": sum(1 for d in detail if d["status"] == "outage"),
    }
    if critiques_hs:
        etat = "outage"
    elif c["modules_down"] or c["modules_degraded"]:
        etat = "degraded"
    elif detail:
        etat = "operational"
    else:
        etat = "unknown"
    return etat, c, detail


def web(lecture: Lecture) -> str:
    d = lecture.donnees or {}
    if lecture.etat != "fresh" or not isinstance(d.get("vhosts"), dict) or not d["vhosts"]:
        return "unknown"
    statuts = [str((v or {}).get("status") or "").lower() for v in d["vhosts"].values() if isinstance(v, dict)]
    if statuts and all(s == "ok" for s in statuts):
        return "operational"
    return "degraded" if any(s in ("ok", "slow", "down", "error") for s in statuts) else "unknown"


def systeme(ressources: Dict[str, Any]) -> str:
    vals = [ressources.get(k) for k in ("cpu_percent", "memory_percent", "disk_percent")]
    connus = [v for v in vals if isinstance(v, (int, float))]
    if not connus:
        return "unknown"
    return "degraded" if any(v >= SEUIL_RESSOURCE for v in connus) else "operational"


def validation(lecture: Lecture) -> Tuple[str, Optional[str]]:
    d = lecture.donnees or {}
    if lecture.etat != "fresh":
        return "unknown", None
    profil = d.get("profil_actif") if isinstance(d.get("profil_actif"), str) else None
    partiel = d.get("partiel")
    if isinstance(partiel, list) and partiel:
        return "degraded", profil
    return "operational", profil


def global_(composants: Dict[str, str], critique_hs: bool) -> str:
    if critique_hs:
        return "outage"
    e = pire(list(composants.values()))
    return "degraded" if e == "outage" else e
