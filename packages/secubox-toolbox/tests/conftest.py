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
#
# IMPORT TOLERANT, ET C'EST INDISPENSABLE. `secubox_core.testing` tire
# `secubox_core/__init__` qui tire `auth` qui tire **fastapi**. Or plusieurs
# jobs CI n'installent que pytest pour lancer une suite qui n'a rien d'une API
# (`scripts/tests/test_check_dashboard_cache.py`) : un import dur y fait
# echouer le CHARGEMENT DU CONFTEST, donc toute la suite, sur un
# ModuleNotFoundError qui ne dit rien du vrai sujet. C'est exactement ce qui
# est arrive au premier passage de ce fichier en CI.
#
# Sans fastapi il n'y a de toute facon aucune application a armer : on passe.
try:  # noqa: SIM105
    from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb

    _sbx_tdb()
except ImportError:
    pass


# ── GARDE D'ADMINISTRATION (#1783) ────────────────────────────────────────
# L'application refuse désormais toute route d'administration sans l'en-tête
# que nginx pose après auth_request. Les suites existantes testent la LOGIQUE
# de ces routes, pas leur accès : la garde leur est ouverte par défaut. Un test
# marqué `garde_reelle` (tests/test_garde_admin_1783.py) la garde fermée.
import pytest as _pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "garde_reelle: garde d'administration réelle (#1783)")


@_pytest.fixture(autouse=True)
def _garde_admin_ouverte_par_defaut(request, monkeypatch):
    if request.node.get_closest_marker("garde_reelle"):
        return
    mod = _sys.modules.get("secubox_toolbox.app")
    if mod is not None and hasattr(mod, "_garde_admise"):
        monkeypatch.setattr(mod, "_garde_admise", lambda req: True)

