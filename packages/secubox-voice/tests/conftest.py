# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import sys
from pathlib import Path

# Le paquet `api` vit à la racine du module, pas dans un site-packages : on
# l'expose comme le fait l'unité systemd (WorkingDirectory=/usr/share/secubox/voice).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# secubox_core est fourni par secubox-core sur la box ; en test on se contente
# d'un substitut minimal pour ne pas dépendre de son installation.
import types
if "secubox_core" not in sys.modules:
    core = types.ModuleType("secubox_core")
    logger = types.ModuleType("secubox_core.logger")
    import logging
    logger.get_logger = lambda n: logging.getLogger(n)
    auth = types.ModuleType("secubox_core.auth")
    auth.router = None
    auth.require_jwt = lambda: None
    auth.require_lecture = lambda: None
    sys.modules["secubox_core"] = core
    sys.modules["secubox_core.logger"] = logger
    sys.modules["secubox_core.auth"] = auth
