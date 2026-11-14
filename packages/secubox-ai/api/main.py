# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-ai : module IA de SecuBox (#3583), porté du POC gk0.

Les routes sont servies à la racine du socket `/run/secubox/ai.sock` ; nginx retire le préfixe public
`/api/v1/ai` (même convention que secubox-ai-gateway), les URL de la page restent donc celles du POC.
Les tâches suivantes ajoutent leurs routes par `app.include_router(<module>.routeur)`.
Toute route est gardée par `require_jwt`, sauf `GET /health`.
"""
from fastapi import APIRouter, Depends, FastAPI

from secubox_core.auth import require_jwt

VERSION = "0.1.0"

# Valeur provisoire, remplacée quand le moteur local existe (tâche 4).
MOTEUR_INCONNU = "inconnu"

ROUTEUR = APIRouter(prefix="")


def etat_moteur() -> str:
    return MOTEUR_INCONNU


@ROUTEUR.get("/health")
async def health():
    return {"status": "ok", "module": "ai"}


@ROUTEUR.get("/status", dependencies=[Depends(require_jwt)])
async def status():
    return {"module": "ai", "version": VERSION, "moteur": etat_moteur()}


app = FastAPI(title="SecuBox AI", version=VERSION)
app.include_router(ROUTEUR)
