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

# Le harnais represente un client de tableau de bord LAN (#1256) : mode arme +
# en-tete LAN. `require_jwt` n'est PAS satisfait pour autant — les tests qui
# verifient un refus continuent de le voir.
from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb  # noqa: E402
_sbx_tdb()
