# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Seed secubox_core config so `api.main` imports without reading /etc.

If secubox_core is not importable in this environment, the API tests self-skip
cleanly (see test_api.py) rather than erroring at collection time.
"""
try:
    import secubox_core.config as _cfgmod
    _cfgmod._CONFIG = {
        "maigret": {
            "enabled": True,
            "container_name": "maigret",
            "lxc_ip": "10.100.0.42",
        },
    }
except Exception:  # pragma: no cover - handled by per-test skip
    pass
