# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Charge le module `ancre` de secubox-p2p (#3100) : une seule définition de l'empreinte et de l'écriture de l'ancre.

Chargé par chemin de fichier (pas par `import api.ancre`) : le paquet `api` de premier-pas porte le même nom que celui de secubox-p2p."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

# Installé par secubox-p2p ; le second chemin sert à l'arbre de sources (tests).
CHEMINS = (Path("/usr/lib/secubox/p2p/api/ancre.py"),
           Path(__file__).resolve().parents[2] / "secubox-p2p" / "api" / "ancre.py")


def charge() -> ModuleType:
    """Le module ancre, ou RuntimeError s'il n'est pas livré sur cette box."""
    for chemin in CHEMINS:
        if chemin.is_file():
            spec = importlib.util.spec_from_file_location("secubox_p2p_ancre", chemin)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise RuntimeError("module ancre de secubox-p2p absent (/usr/lib/secubox/p2p/api/ancre.py) : installez secubox-p2p")
