# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-ephemeride : le paquet et common/ sur sys.path ; la configuration de la box est factice (aucun fichier /etc lu)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))

import secubox_core.config as _cfg  # noqa: E402

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
