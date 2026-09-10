# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# conftest.py (racine) — SecuBox-Deb
"""`common/` sur le chemin d'import, pour toute suite du dépôt.

POURQUOI ICI ET PAS DANS CHAQUE PAQUET. Les 181 paquets déclarent tous
`secubox-core` dans `debian/control` : sur une board, `secubox_core` est
importable, point. Seul le harnais de test l'ignorait, et chaque suite le
rattrapait — ou pas — dans son propre conftest. Le passage du parc en lecture
gardée (#1256) a rendu l'écart visible d'un coup : `api/main.py` importe
désormais `secubox_core.auth` partout, et une douzaine de suites ont cessé de
collecter avec un `ModuleNotFoundError` qui ne disait rien du vrai problème.

Le symptôme le plus trompeur était `ImportError: cannot import name
require_lecture from secubox_core.auth (unknown location)` : sans ce chemin,
Python résolvait `secubox_core` en paquet-espace-de-noms VIDE au lieu du vrai
module — un import qui échoue en désignant le bon nom pour la mauvaise raison.

pytest charge le conftest de la racine pour toute suite collectée en dessous,
y compris lancée par chemin explicite (`pytest packages/<x>/tests`), qui est
le mode imposé par `pytest.ini` à cause de la collision des dossiers `api/`.
"""
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
_COMMON = str(RACINE / "common")

if _COMMON not in sys.path:
    sys.path.insert(0, _COMMON)

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
