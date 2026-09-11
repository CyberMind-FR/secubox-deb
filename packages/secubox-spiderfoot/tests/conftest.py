# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Seed secubox_core config so `api.main` imports without reading /etc.

If secubox_core is not importable in this environment, the API tests self-skip
cleanly (see test_api.py) rather than erroring at collection time.
"""
try:
    import secubox_core.config as _cfgmod
    _cfgmod._CONFIG = {
        "spiderfoot": {
            "enabled": True,
            "container_name": "spiderfoot",
            "lxc_ip": "10.100.0.43",
            "sf_port": 5001,
        },
    }
except Exception:  # pragma: no cover - handled by per-test skip
    pass

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
