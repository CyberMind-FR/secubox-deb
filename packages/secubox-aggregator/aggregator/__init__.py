# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: secubox-aggregator

Master ASGI gateway that mounts each SecuBox module's FastAPI as a sub-app
under /api/v1/<module>. Eliminates the ~30 MB Python interpreter overhead
duplicated across 100+ per-module uvicorn processes (Phase 7 / #496).
"""

__version__ = "0.1.0"
