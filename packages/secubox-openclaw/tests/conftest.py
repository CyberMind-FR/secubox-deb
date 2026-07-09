# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Seed secubox_core config so `api.main` imports without reading /etc."""
import secubox_core.config as _cfgmod
_cfgmod._CONFIG = {
    "openclaw": {
        "enabled": True,
        "container_name": "openclaw",
        "lxc_ip": "10.100.0.41",
        "owned_domains": ["gk2.secubox.in"],
    },
}
