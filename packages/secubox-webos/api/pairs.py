# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — services offerts par les autres box du maillage (#3133).

Lit le cache fichier écrit par l'annuaire. Le cache vient de données publiées par
d'autres nœuds : il est traité comme une entrée non fiable (bornes, types,
https seulement) et tout élément malformé est écarté sans faire échouer la lecture.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

CACHE = Path("/var/lib/secubox/annuaire/services-pairs.json")

MAX_OCTETS = 1_000_000
MAX_PAIRS = 32
MAX_SERVICES = 64
MAX_NOM = 63
MAX_ENDPOINT = 255
MAX_CHAMP = 255
MAX_DESCRIPTION = 255


def _vide() -> Dict[str, Any]:
    return {"pairs": [], "genere": None, "disponible": False}


def _texte(v: Any, borne: int) -> Optional[str]:
    """Chaîne bornée, sinon None."""
    if isinstance(v, str) and len(v) <= borne:
        return v
    return None


def _service(brut: Any) -> Optional[Dict[str, str]]:
    if not isinstance(brut, dict):
        return None
    nom = _texte(brut.get("nom"), MAX_NOM)
    ep = _texte(brut.get("endpoint"), MAX_ENDPOINT)
    if not nom or not ep or not ep.startswith("https://") or len(ep) <= len("https://"):
        return None
    desc = _texte(brut.get("description"), MAX_DESCRIPTION)
    return {"nom": nom, "endpoint": ep, "description": desc or ""}


def _pair(brut: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(brut, dict):
        return None
    champs: Dict[str, str] = {}
    for cle in ("did", "boxname", "domaine", "mesh_ip"):
        champs[cle] = _texte(brut.get(cle), MAX_CHAMP) or ""
    brut_svc = brut.get("services")
    services: List[Dict[str, str]] = []
    if isinstance(brut_svc, list):
        for s in brut_svc[:MAX_SERVICES]:
            ok = _service(s)
            if ok:
                services.append(ok)
    return {**champs, "services": services}


def lire_cache(chemin: Optional[Path] = None) -> Dict[str, Any]:
    """Cache des services des pairs, assaini ; jamais d'exception."""
    chemin = chemin or CACHE  # résolu à l'appel (CACHE substituable en test)
    try:
        if chemin.stat().st_size > MAX_OCTETS:
            return _vide()
        doc = json.loads(chemin.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _vide()
    if not isinstance(doc, dict) or doc.get("version") != 1:
        return _vide()
    brut = doc.get("pairs")
    if not isinstance(brut, list):
        return _vide()
    pairs: List[Dict[str, Any]] = []
    for p in brut[:MAX_PAIRS]:
        ok = _pair(p)
        if ok:
            pairs.append(ok)
    return {"pairs": pairs, "genere": _texte(doc.get("genere"), 64), "disponible": True}
