# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecture des fichiers d'état du Toolbox (niveaux par pair, exclusions) — sans FastAPI, partagée par l'API et par l'instantané root (#2447)."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

TOOLBOX_DIR = Path("/var/lib/secubox/toolbox")


def _json(chemin: Path) -> Optional[dict]:
    try:
        d = json.loads(chemin.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def niveaux(dossier: Optional[Path] = None) -> dict:
    """Niveaux d'inspection par pair WireGuard (off/passive/active/reel) et répartition cumulée du Toolbox ; une source absente donne null."""
    dossier = dossier or TOOLBOX_DIR
    rl = _json(dossier / "peer-rlevel.json")
    cum = _json(dossier / "cumulative-cache.json")
    out: dict[str, Any] = {"defaut": None, "pairs": None, "repartition_pairs": None, "niveaux_clients": None, "evenements_7j": None}
    if rl is not None:
        pairs = rl.get("peers") or {}
        out["defaut"] = rl.get("defaults")
        out["pairs"] = len(pairs)
        out["repartition_pairs"] = dict(Counter(str((p or {}).get("chosen") or "défaut") for p in pairs.values()))
    if cum is not None:
        out["niveaux_clients"] = cum.get("level_distribution_7d")
        out["evenements_7j"] = (cum.get("events") or {}).get("total_7d")
    return out


def _lignes(chemin: Path) -> Optional[list]:
    try:
        return [l.strip() for l in chemin.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        return None


def exclusions(dossier: Optional[Path] = None) -> dict:
    """Hôtes que l'inspection ne déchiffre pas (bypass : laissés passer ; splice : relayés sans déchiffrer) et motifs de filtre désactivés."""
    dossier = dossier or TOOLBOX_DIR
    return {"bypass": _lignes(dossier / "mitm-bypass.conf"), "splice": _lignes(dossier / "splice-learned.txt"),
            "filtres_desactives": _lignes(dossier / "mitm-filter-disabled.txt")}
