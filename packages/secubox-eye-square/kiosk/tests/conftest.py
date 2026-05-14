# packages/secubox-eye-square/kiosk/tests/conftest.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""pytest conftest for the kiosk test package — adds the kiosk source dir to sys.path."""
from __future__ import annotations

import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))
