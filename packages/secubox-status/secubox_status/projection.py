# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Projection PUBLIQUE d'un relevé (spec §4, arbitrage §11.1 : fichier statique, jamais une route anonyme).

Liste blanche : on ne recopie que des champs nommés ici. Ni noyau, ni nom d'hôte, ni adresses, ni sources
détaillées ; ressources et inventaire des modules seulement si `[public]` le demande explicitement.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import SCHEMA_PUBLIC, VERSION


def noeud_public(releve: Dict[str, Any], cfg_public: Dict[str, Any], heures: List[Dict[str, str]],
                 dispo_30j: Optional[float], detail: List[Dict[str, Any]], id_public: str = "appliance") -> Dict[str, Any]:
    """`id_public` : le `node_id` réglé EXPLICITEMENT, sinon un alias neutre — jamais le nom de la machine."""
    h = releve["health"]
    n: Dict[str, Any] = {
        "id": id_public,
        "status": h["overall"],
        "components": {k: h[k] for k in ("services", "web", "system", "validation") if k in h},
        "last_seen": releve["collected_at"],
        "measurement_complete": all(v == "fresh" for v in releve["sources"].values()),
        "signature_verified": None,     # jalon 2 : relevé signé par l'identité du nœud
        "externally_confirmed": None,   # sonde externe : jalon 3
        "availability_30d": dispo_30j,
        "hours": heures,
    }
    if cfg_public.get("expose_resources"):
        n["resources"] = {k: releve["resources"].get(k)
                          for k in ("cpu_percent", "memory_percent", "disk_percent", "temperature_celsius")}
    if cfg_public.get("expose_module_inventory"):
        n["modules"] = [{"id": d["id"], "status": d["status"]} for d in detail]
    else:
        c = releve["counts"]
        n["counts"] = {k: c.get(k) for k in ("modules_total", "modules_ok", "modules_degraded", "modules_down")}
    return n


_ETATS = ("operational", "degraded", "outage", "maintenance", "unknown")
_NOM = re.compile(r"[a-z0-9][a-z0-9 -]{0,62}")
_HEURE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})")


def _etat(v: Any) -> str:
    return v if v in _ETATS else "unknown"


def _entier(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10000 else None


def noeud_pair(rec: Dict[str, Any], frais: bool) -> Dict[str, Any]:
    """Un pair vérifié par l'Annuaire (#3626), REVALIDÉ ici (le fichier vient d'un autre compte) : nom de la fiche
    signée (jamais le hostname déclaré), énumérations, bornes. Relevé trop vieux ou nom contesté = inconnu."""
    nom = str(rec.get("nom") or "")
    nom = nom if _NOM.fullmatch(nom) else "box du maillage"
    conteste = rec.get("nom_conteste") is True
    sources = rec.get("sources") if isinstance(rec.get("sources"), dict) else {}
    dispo = rec.get("availability_30d")
    heures = [{"hour": h["hour"], "status": _etat(h.get("status"))}
              for h in (rec.get("hours") if isinstance(rec.get("hours"), list) else [])[-24:]
              if isinstance(h, dict) and isinstance(h.get("hour"), str) and _HEURE.fullmatch(h["hour"])]
    vu = rec.get("collected_at")
    return {
        "id": nom + (" (nom contesté)" if conteste else ""),
        "status": _etat(rec.get("overall")) if frais and not conteste else "unknown",
        "components": {k: _etat(v) for k, v in (rec.get("components") or {}).items()
                       if k in ("services", "web", "system", "validation")},
        "last_seen": vu if isinstance(vu, str) and _HEURE.fullmatch(vu) else None,
        "measurement_complete": bool(sources) and all(v == "fresh" for v in sources.values()) and frais,
        "signature_verified": rec.get("signature_verified") is True,
        "externally_confirmed": None,
        "availability_30d": float(dispo) if isinstance(dispo, (int, float)) and not isinstance(dispo, bool)
                            and 0 <= dispo <= 100 else None,
        "hours": heures,
        "counts": {k: _entier((rec.get("counts") or {}).get(k))
                   for k in ("modules_total", "modules_ok", "modules_degraded", "modules_down")},
    }


def noeud_absent(ind: Dict[str, Any]) -> Dict[str, Any]:
    """Une box du maillage sans relevé recevable : affichée, état inconnu, avec la raison (jamais une box qui disparaît)."""
    nom = str(ind.get("nom") or "")
    return {"id": nom if _NOM.fullmatch(nom) else "box du maillage", "status": "unknown", "components": {}, "last_seen": None,
            "measurement_complete": False, "signature_verified": None, "externally_confirmed": None,
            "availability_30d": None, "hours": [], "counts": {}, "raison": str(ind.get("raison") or "")[:80]}


def flotte(noeuds: List[Dict[str, Any]], genere: str) -> Dict[str, Any]:
    compte = {e: sum(1 for n in noeuds if n["status"] == e) for e in ("operational", "degraded", "outage", "unknown")}
    if not noeuds or compte["unknown"] == len(noeuds):
        etat = "unknown"
    elif compte["outage"] or compte["degraded"]:
        etat = "degraded"
    else:
        etat = "operational"
    return {
        "schema": SCHEMA_PUBLIC, "version": VERSION, "generated_at": genere,
        "fleet": {"status": etat, "nodes_total": len(noeuds), "nodes_operational": compte["operational"],
                  "nodes_degraded": compte["degraded"] + compte["outage"], "nodes_unknown": compte["unknown"]},
        "nodes": noeuds,
    }
