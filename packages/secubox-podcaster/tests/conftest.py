# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Rends `secubox_core` importable hors installation système.

À l'exécution, `secubox-core` est un paquet Debian installé sur le PYTHONPATH ;
en test on ajoute simplement sa source (`common/`) au chemin, pour que
`api.importer` (qui en dépend) s'importe comme il le fait sur la board."""
import sys
from pathlib import Path

_COMMON = Path(__file__).resolve().parents[3] / "common"
if _COMMON.is_dir() and str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))

# Le harnais represente un client de tableau de bord LAN (#1256) : mode arme +
# en-tete LAN. `require_jwt` n'est PAS satisfait pour autant — les tests qui
# verifient un refus continuent de le voir.
from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb  # noqa: E402
_sbx_tdb()
