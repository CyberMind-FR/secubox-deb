# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Chemins de secubox-mirrornet (#3645). Surchargeables pour les tests seulement."""
from __future__ import annotations

import os
from pathlib import Path

ETAT = Path(os.environ.get("SBX_MIRRORNET_ETAT", "/var/lib/secubox-mirrornet"))
BASE = Path(os.environ.get("SBX_MIRRORNET_DB", str(ETAT / "mirrornet.db")))
CONF = Path(os.environ.get("SBX_MIRRORNET_CONF", "/etc/secubox/mirrornet.toml"))
