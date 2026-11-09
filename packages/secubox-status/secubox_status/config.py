# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Configuration `/etc/secubox/status.toml` : valeurs par défaut sûres, un fichier absent ou cassé ne bloque rien."""
from __future__ import annotations

import logging
import re
import tomllib
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger("secubox-status")

CONFIG = Path("/etc/secubox/status.toml")
ETAT = Path("/var/lib/secubox-status")

DEFAUTS: Dict[str, Any] = {
    "status": {"node_id": "", "node_role": "aggregator"},
    "history": {"retention_days": 90},
    "sources": {
        "vhosts": {"enabled": True, "path": "/var/cache/secubox/health/status.json", "stale_after_seconds": 300},
        "modules": {"enabled": True, "path": "/var/cache/secubox/health/modules.json", "stale_after_seconds": 300},
        "profiles": {"enabled": True, "path": "/var/lib/secubox/profiles/validation/releve.json",
                     "stale_after_seconds": 900},
        "system": {"enabled": True},
    },
    "public": {"expose_resources": False, "expose_module_inventory": False},
}

_NOM = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _fusion(base: Dict[str, Any], ajout: Dict[str, Any]) -> Dict[str, Any]:
    sortie = dict(base)
    for k, v in ajout.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            sortie[k] = _fusion(base[k], v)
        elif k in base and type(v) is type(base[k]):
            sortie[k] = v
        elif k not in base:
            sortie[k] = v
    return sortie


def charger(chemin: Path = CONFIG) -> Dict[str, Any]:
    """Défauts complétés par le fichier ; une valeur d'un autre type que le défaut est ignorée."""
    try:
        brut = tomllib.loads(chemin.read_text(encoding="utf-8"))
    except FileNotFoundError:
        brut = {}
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        log.warning("status.toml illisible (%s) : valeurs par défaut", e)
        brut = {}
    cfg = _fusion(DEFAUTS, brut if isinstance(brut, dict) else {})
    if cfg["status"]["node_role"] not in ("aggregator", "agent"):
        cfg["status"]["node_role"] = "aggregator"
    return cfg


def nom_de_noeud(cfg: Dict[str, Any], hote: str) -> str:
    """Identifiant d'affichage du nœud (jamais une preuve d'identité : celle-ci viendra du DID au jalon 2)."""
    for candidat in (cfg["status"].get("node_id") or "", hote.split(".")[0].lower()):
        if _NOM.match(candidat):
            return candidat
    return "inconnu"
