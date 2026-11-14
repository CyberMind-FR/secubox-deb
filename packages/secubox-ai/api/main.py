# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-ai : module IA de SecuBox (#3583), porté du POC gk0.

Les routes sont servies à la racine du socket `/run/secubox/ai.sock` ; nginx retire le préfixe public
`/api/v1/ai` (même convention que secubox-ai-gateway), les URL de la page restent donc celles du POC.
Les tâches suivantes ajoutent leurs routes par `app.include_router(<module>.routeur)`.
Toute route est gardée par `require_jwt`, sauf `GET /health`.
La veille des menaces (relevés de fond, résumé automatique) vit avec l'application : lancée au démarrage, annulée à
l'arrêt. Les tests par `httpx.ASGITransport` ne la lancent pas (pas d'événements de cycle de vie).
"""
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI

from secubox_core.auth import require_jwt

from api import dialogue, documents, memoire, menaces, moteurs, reglages, taches

VERSION = "0.1.0"

ROUTEUR = APIRouter(prefix="")


@ROUTEUR.get("/health")
async def health():
    return {"status": "ok", "module": "ai"}


@ROUTEUR.get("/status", dependencies=[Depends(require_jwt)])
async def status():
    return {"module": "ai", "version": VERSION, "moteur": await moteurs.etat(), "preferences": reglages.etat_prefs()}


@asynccontextmanager
async def cycle_de_vie(_app):
    menaces.charger_instantanes()
    menaces.demarrer_veille()
    try:
        yield
    finally:
        await menaces.arreter_veille()


app = FastAPI(title="SecuBox AI", version=VERSION, lifespan=cycle_de_vie)
app.include_router(ROUTEUR)
app.include_router(reglages.routeur)
app.include_router(moteurs.routeur)
app.include_router(taches.routeur)
app.include_router(memoire.routeur)
app.include_router(dialogue.routeur)
app.include_router(documents.routeur)
app.include_router(menaces.routeur)
