# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Rends `secubox_core` importable hors installation système (source dans
`common/`), pour que `api.importer` s'importe comme sur la board."""
import sys
from pathlib import Path

_COMMON = Path(__file__).resolve().parents[3] / "common"
if _COMMON.is_dir() and str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))
