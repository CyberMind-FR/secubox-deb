# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import sys
from pathlib import Path

R = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(R / "common"), str(R / "packages" / "secubox-sbxid")]
import secubox_core.config as _conf  # noqa: E402
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or [R / "secubox.conf.example"]
