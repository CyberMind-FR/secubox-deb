# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: courbes — API des pages Courbes (/grafana/) et Glances (/glances/), SANS secubox-metrics (#2865).

Servi par secubox-groupd (groupable.d) sur /run/secubox/courbes.sock, joignable en /api/v1/courbes/… : l'agrégateur RETIRE le préfixe, les routes sont donc à la racine.
Aucun processus de plus, aucun fichier nginx. Le relevé et l'instantané viennent de la bibliothèque `secubox_courbes` (stdlib + psutil)."""
import asyncio
from typing import Optional

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from secubox_core.auth import require_lecture
from secubox_courbes import serie, systeme

app = FastAPI(title="SecuBox Courbes", version="0.1.0")


@app.get("/health")
async def health():
    return {"status": "ok", "module": "courbes", "version": "0.1.0"}


@app.get("/series", dependencies=[Depends(require_lecture)])
def series(duree: float = 3600, points: int = 240, depuis: Optional[float] = None, jusqua: Optional[float] = None):
    """Courbes (#2765) : CPU, mémoire, charge, débit, connexions, disque. Fenêtre `duree` (s) ou [depuis, jusqua] ; `points` tranches."""
    return JSONResponse(content=serie.vue(duree, points, depuis=depuis, jusqua=jusqua), headers={"Cache-Control": "no-store"})


@app.get("/systeme", dependencies=[Depends(require_lecture)])
async def systeme_en_direct():
    """Instantané système rapide (#2767) : CPU par cœur, mémoire, disques, réseau, top des processus, hors du fil de l'agrégateur."""
    mesures = await asyncio.get_running_loop().run_in_executor(None, systeme.instantane)
    return JSONResponse(content=mesures, headers={"Cache-Control": "no-store"})
