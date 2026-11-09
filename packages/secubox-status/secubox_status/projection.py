# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Projection PUBLIQUE d'un relevé (spec §4, arbitrage §11.1 : fichier statique, jamais une route anonyme).

Liste blanche : on ne recopie que des champs nommés ici. Ni noyau, ni nom d'hôte, ni adresses, ni sources
détaillées ; ressources et inventaire des modules seulement si `[public]` le demande explicitement.
"""
from __future__ import annotations

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
