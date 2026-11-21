# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Connecteur status : santé des modules (modules.json), périmée après perime_apres_s secondes."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..store import Releve
from ._commun import empreinte, suffixe_valide

SOURCE = "status"
FUTUR_MAX_S = 60  # horodatage plus loin dans le futur : horloge fausse, donc périmé


def _epoch(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
    return None


def _inconnu(motif: str) -> Releve:
    return Releve(source=SOURCE, etat="unknown", motif=motif, empreinte="")


def lire(modules: Path, hote: str, maintenant: float, perime_apres_s: int = 300) -> Releve:
    try:
        data = json.loads(Path(modules).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return _inconnu(f"modules.json illisible : {type(e).__name__}")
    brut = data.get("modules") if isinstance(data, dict) else None
    if not isinstance(brut, dict):
        return _inconnu("modules.json de forme inattendue")
    horodatage = data.get("timestamp")
    ts = _epoch(horodatage)
    if ts is None:
        tous = [_epoch(m.get("timestamp")) for m in brut.values() if isinstance(m, dict)]
        tous = [t for t in tous if t is not None]
        ts = max(tous) if tous else None
        horodatage = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None
    perime = ts is None or maintenant - ts > perime_apres_s or ts - maintenant > FUTUR_MAX_S
    noeud = f"node:{hote}"
    entites: List[Dict[str, Any]] = [{"id": noeud, "label": hote, "attributes": {}}]
    rels: List[Dict[str, Any]] = []
    for nom, m in brut.items():
        if not suffixe_valide(nom) or not isinstance(m, dict):
            continue
        overall = "unknown" if perime else str(m.get("overall") or "unknown")
        sid = f"service:{nom}"
        entites.append({"id": sid, "label": nom,
                        "attributes": {"overall": overall, "critical": bool(m.get("critical"))}})
        rels.append({"src": sid, "dst": noeud, "type": "HOSTED_ON", "evidence_type": "reported",
                     "confidence": 1.0, "justification": f"santé des modules du {horodatage}",
                     "source_module": "status"})
    return Releve(source=SOURCE, etat="unknown" if perime else "ok",
                  motif="modules.json périmé" if perime else None,
                  entites=entites, relations=rels, empreinte=empreinte(entites, rels))
