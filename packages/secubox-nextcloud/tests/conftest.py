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
