# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Pytest configuration for secubox-eye-remote tests."""
import sys
from pathlib import Path

# Add package root to Python path
pkg_root = Path(__file__).parent.parent
sys.path.insert(0, str(pkg_root))

# ET `common/`, qui porte secubox_core (#1256). Le paquet en dépend déjà dans
# debian/control ; seul le harnais de test l'ignorait, et api/main.py importe
# desormais secubox_core.auth.require_jwt — sans ce chemin, la collecte casse
# sur un ModuleNotFoundError qui ne dit rien du vrai probleme.
sys.path.insert(0, str(pkg_root.parent.parent / "common"))
