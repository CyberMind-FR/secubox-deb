# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Test bootstrap.

`api.main` calls `get_config("nextcloud")` at import time. On this dev box
`/etc/secubox/secubox.conf` is root:secubox 0640 and unreadable by the
account running the test suite, so a bare import blows up with a
PermissionError before any test body (and any monkeypatch inside it) gets a
chance to run. Pre-seed the shared `secubox_core.config` module-level cache
here so `_load()` returns immediately without ever touching the file --
mirrors the sibling-module pattern of stubbing config for tests (see
packages/secubox-metrics/tests/test_config_helpers.py) but seeds instead of
just resetting, since our failure mode is a read, not a stale cache.
"""
import secubox_core.config as _cfgmod

_cfgmod._CONFIG = {
    "nextcloud": {
        "enabled": True,
        "http_port": 8080,
        "container_name": "nextcloud",
        "lxc_path": "/tmp/secubox-nextcloud-test/lxc",
        "data_path": "/tmp/secubox-nextcloud-test/data",
        "domain": "nc.gk2.secubox.in",
        "ssl_enabled": False,
    },
}

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
