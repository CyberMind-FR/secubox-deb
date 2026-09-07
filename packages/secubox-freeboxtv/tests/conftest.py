# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Ajoute api/ et common/ (secubox_core) au sys.path pour les tests."""
import sys
from pathlib import Path

_pkg = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg))
_repo = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_repo / "common"))
