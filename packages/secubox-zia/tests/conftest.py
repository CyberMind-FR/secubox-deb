# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Ajoute le paquet (pour importer `api` comme package) et common/ au sys.path."""
import sys
from pathlib import Path

# packages/secubox-zia/  → permet « import api.capabilities » (imports relatifs).
_pkg_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg_root))

# racine du dépôt → common/ (secubox_core), utilisé par api.main.
_repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_repo_root / "common"))
