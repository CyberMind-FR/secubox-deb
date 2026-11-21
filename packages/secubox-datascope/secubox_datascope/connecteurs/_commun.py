# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Briques communes aux connecteurs : identifiants valides, empreinte, dates."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

_SUFFIXE = re.compile(r"[A-Za-z0-9:._-]{1,128}")


def suffixe_valide(s: Any) -> bool:
    return isinstance(s, str) and _SUFFIXE.fullmatch(s) is not None


def empreinte(entites: List[Dict[str, Any]], relations: List[Dict[str, Any]]) -> str:
    """SHA-256 du JSON trié : indépendant de l'ordre des lignes."""
    e = sorted(entites, key=lambda x: x["id"])
    r = sorted(relations, key=lambda x: (x["src"], x["dst"], x["type"]))
    blob = json.dumps({"entites": e, "relations": r}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def jour(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d")
