# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""`common/` sur le chemin d'import ; une config ILLISIBLE n'est pas une config absente (même cas que secubox-mail, #1014).

Sur un poste de développement `/etc/secubox/secubox.conf` existe mais appartient à root : `secubox_core.config` ouvre le
fichier à l'IMPORT de l'API et lève PermissionError. On pré-remplit son cache avec la valeur par défaut qu'il aurait choisie
sans fichier."""
import sys
from pathlib import Path

_COMMON = str(Path(__file__).resolve().parents[4] / "common")
if _COMMON not in sys.path:
    sys.path.insert(0, _COMMON)

try:
    open("/etc/secubox/secubox.conf", "rb").close()
except OSError:
    from secubox_core import config as _cfg
    if _cfg._CONFIG is None:
        _cfg._CONFIG = {
            "global": {"hostname": "secubox", "board": "unknown"},
            "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "dev-secret"},
            "dns-provider": {},
        }

try:  # noqa: SIM105 — sans fastapi (CI minimale) il n'y a pas d'application à armer
    from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb

    _sbx_tdb()
except ImportError:
    pass
