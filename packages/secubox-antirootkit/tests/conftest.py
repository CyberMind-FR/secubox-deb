# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# `common/` sur le chemin d'import (#1256).
#
# Ce paquet a sa PROPRE racine pytest (pytest.ini / pyproject.toml a sa
# racine), donc le conftest.py du depot n'est pas charge pour lui : le chemin
# doit etre pose ici aussi. Sans lui, `from secubox_core.auth import
# require_lecture` — que api/main.py fait depuis le passage du parc en lecture
# gardee — echoue a la collecte.
import sys as _sys
from pathlib import Path as _Path
_COMMON = str(_Path(__file__).resolve().parents[3] / "common")
if _COMMON not in _sys.path:
    _sys.path.insert(0, _COMMON)

# Le harnais represente un client de tableau de bord LAN (#1256) : mode arme +
# en-tete LAN. `require_jwt` n'est PAS satisfait pour autant — les tests qui
# verifient un refus continuent de le voir.
from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb  # noqa: E402
_sbx_tdb()
