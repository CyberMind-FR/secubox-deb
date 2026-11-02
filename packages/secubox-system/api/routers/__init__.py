# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: api.routers — Routers FastAPI système.

Chaque import est isolé (#3401) : un routeur cassé (metrics importe `core`, absent du paquet installé) ne doit pas
empêcher les autres (ssh, remote_ui) de se charger ; api/main.py importe et journalise chaque routeur lui-même.
"""
try:
    from .metrics import router as metrics_router
except ImportError:
    metrics_router = None
try:
    from .remote_ui import router as remote_ui_router
except ImportError:
    remote_ui_router = None

__all__ = ["metrics_router", "remote_ui_router"]
