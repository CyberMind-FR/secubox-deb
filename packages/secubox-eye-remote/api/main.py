"""
SecuBox Eye Remote — FastAPI Application
Management API for Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

# Routers will be added in Task 10
# from .routers import devices, pairing, metrics, websocket


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    yield
    # Shutdown


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


# Include routers (will be uncommented in Task 10)
# app.include_router(devices.router, prefix="/devices", tags=["devices"])
# app.include_router(pairing.router, prefix="/pairing", tags=["pairing"])
# app.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
# app.include_router(websocket.router, tags=["websocket"])
