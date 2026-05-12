# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: api.routers — Routers FastAPI système."""
from .metrics import router as metrics_router
from .remote_ui import router as remote_ui_router

__all__ = ["metrics_router", "remote_ui_router"]
