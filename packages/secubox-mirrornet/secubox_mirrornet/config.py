# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Chemins et réglages de secubox-mirrornet (#3645, #3647). Chemins surchargeables pour les tests seulement."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Dict

ETAT = Path(os.environ.get("SBX_MIRRORNET_ETAT", "/var/lib/secubox-mirrornet"))
BASE = Path(os.environ.get("SBX_MIRRORNET_DB", str(ETAT / "mirrornet.db")))
CONF = Path(os.environ.get("SBX_MIRRORNET_CONF", "/etc/secubox/mirrornet.toml"))
EXPORT = Path(os.environ.get("SBX_MIRRORNET_EXPORT", "/var/lib/secubox/annuaire/mirrornet-export.json"))
ANNUAIRE_SOCK = os.environ.get("SBX_MIRRORNET_ANNUAIRE_SOCK", "/run/secubox/annuaire.sock")

DEFAUTS: Dict[str, Any] = {"confiance_min": "LIMITED", "grace_s": 432000, "intervalle_s": 60}
_NIVEAUX = ("OBSERVER", "LIMITED", "PARTNER", "TRUSTED")


def reglages() -> Dict[str, Any]:
    """Réglages effectifs : un fichier absent, illisible ou une valeur hors bornes retombent sur le défaut."""
    r = dict(DEFAUTS)
    try:
        with open(CONF, "rb") as f:
            d = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return r
    c = (d.get("catalogue") or {}).get("confiance_min")
    if c in _NIVEAUX:
        r["confiance_min"] = c
    g = (d.get("abonnements") or {}).get("grace_s")
    if type(g) is int and 0 <= g <= 90 * 86400:
        r["grace_s"] = g
    i = (d.get("synchro") or {}).get("intervalle_s")
    if type(i) is int and 10 <= i <= 3600:
        r["intervalle_s"] = i
    return r
