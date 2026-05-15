# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Backward-compat shim — re-exports secubox_common.modules.

The legacy in-package Module dataclass had `radius` and `unit` fields.
`radius` is now a layout property of SquareDashboard.RING_RADII (each
form factor uses different radii — round Pi Zero W used 214..149,
square Pi 4B/400 uses 200..125). `unit` was never read in production.
The unit-test that asserted the old radii is removed alongside this
shim — coverage is fully duplicated in
remote-ui/common/python/secubox_common/tests/test_modules.py.
"""
from secubox_common.modules import Module, MODULES  # noqa: F401
