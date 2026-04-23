"""
SecuBox Eye Remote — FastAPI Application
Management API for Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .routers import devices, pairing, metrics, websocket

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Gere le demarrage et l'arret de l'application:
    - Startup: Demarre la tache de heartbeat WebSocket
    - Shutdown: Nettoyage des connexions
    """
    # Startup
    log.info("Demarrage Eye Remote API v2.0.0")

    # Demarrer le heartbeat WebSocket
    websocket.start_heartbeat()
    log.info("Heartbeat WebSocket demarre")

    yield

    # Shutdown
    log.info("Arret Eye Remote API")


app = FastAPI(
    title="SecuBox Eye Remote API",
    description="Management API for Eye Remote devices",
    version="2.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "eye-remote"}


# Include routers
app.include_router(devices.router, prefix="/api/v1/eye-remote")
app.include_router(pairing.router, prefix="/api/v1/eye-remote")
app.include_router(metrics.router, prefix="/api/v1/eye-remote")
app.include_router(websocket.router, prefix="/api/v1/eye-remote")
