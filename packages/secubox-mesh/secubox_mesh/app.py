# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — entrée Uvicorn (`secubox_mesh.app:app`).
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
import logging.handlers

from fastapi import FastAPI

from . import __version__
from .api import router as mesh_router

# Logger setup (journald-friendly).
_log = logging.getLogger("secubox.mesh")
if not _log.handlers:
    _log.setLevel(logging.INFO)
    _log.addHandler(logging.StreamHandler())

app = FastAPI(
    title="SecuBox MESH",
    version=__version__,
    docs_url=None,        # CSPN : pas d'API doc publique par défaut
    redoc_url=None,
    openapi_url=None,
)

# Mount router : pas de prefix interne — nginx ajoute /api/v1/mesh devant.
app.include_router(mesh_router)
