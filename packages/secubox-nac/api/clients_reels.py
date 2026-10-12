# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Clés de jonction des CLIENTS RÉELS (#2423).

Un client réel regroupe l'appareil vu par le NAC, ses identités du Toolbox et son
activité mesurée par le DPI. La jonction NAC ↔ Toolbox se fait sur une clé d'appareil :
un condensat de la MAC, jamais la MAC. La même dérivation existe côté Toolbox
(`secubox_toolbox/appareils.py`) : un test fige la valeur pour que les deux ne divergent pas.
"""
from __future__ import annotations

import hashlib


def cle_appareil(mac: str) -> str:
    """sha256 de la MAC en minuscules, 12 premiers caractères hexadécimaux."""
    return hashlib.sha256(str(mac).lower().encode()).hexdigest()[:12]
