"""
SecuBox Eye Remote — FastAPI Application
Management API for Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .routers import devices, pairing, metrics


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


# Include routers
app.include_router(devices.router, prefix="/api/v1/eye-remote")
app.include_router(pairing.router, prefix="/api/v1/eye-remote")
app.include_router(metrics.router, prefix="/api/v1/eye-remote")
