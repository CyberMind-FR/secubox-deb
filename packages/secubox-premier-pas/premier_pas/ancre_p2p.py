# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Charge le module `ancre` de secubox-p2p (#3100) : une seule définition de l'empreinte et de l'écriture de l'ancre.

Chargé par chemin de fichier (pas par `import api.ancre`) : le paquet `api` de premier-pas porte le même nom que celui de secubox-p2p."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType

# Production : UNIQUEMENT le chemin installé par secubox-p2p (le module est exécuté en root). Un autre fichier ne se charge que par la variable d'environnement,
# posée par les tests.
INSTALLE = Path("/usr/lib/secubox/p2p/api/ancre.py")
ENV = "SBX_P2P_ANCRE_PY"


def _chemin() -> Path:
    return Path(os.environ.get(ENV) or INSTALLE)


def charge() -> ModuleType:
    """Le module ancre, ou RuntimeError s'il n'est pas livré sur cette box."""
    chemin = _chemin()
    if chemin.is_file():
        spec = importlib.util.spec_from_file_location("secubox_p2p_ancre", chemin)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    raise RuntimeError("module ancre de secubox-p2p absent (/usr/lib/secubox/p2p/api/ancre.py) : installez secubox-p2p")
