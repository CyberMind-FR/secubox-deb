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
from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb  # noqa: E402
_sbx_tdb()
