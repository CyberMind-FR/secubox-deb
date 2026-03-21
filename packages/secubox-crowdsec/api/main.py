"""
secubox-crowdsec — FastAPI application
Port de luci-app-crowdsec-dashboard vers Debian

RPCD source : luci.crowdsec-dashboard
Méthodes complètes : status, decisions, alerts, bouncers, metrics, machines,
           hub, collections, wizard, console, acquisition, settings, etc.
"""
from fastapi import FastAPI
from secubox_core.auth import router as auth_router

from .routers import (
    status,
    decisions,
    alerts,
    bouncers,
    metrics,
    actions,
    hub,
    bouncer_mgmt,
    wizard,
    acquisition,
)

app = FastAPI(
    title="secubox-crowdsec",
    version="1.0.0",
    root_path="/api/v1/crowdsec",
)

app.include_router(auth_router,           prefix="/auth")
app.include_router(status.router,         tags=["status"])
app.include_router(decisions.router,      tags=["decisions"])
app.include_router(alerts.router,         tags=["alerts"])
app.include_router(bouncers.router,       tags=["bouncers"])
app.include_router(metrics.router,        tags=["metrics"])
app.include_router(actions.router,        tags=["actions"])
app.include_router(hub.router,            tags=["hub"])
app.include_router(bouncer_mgmt.router,   tags=["bouncer-mgmt"])
app.include_router(wizard.router,         tags=["wizard"])
app.include_router(acquisition.router,    tags=["acquisition"])


@app.get("/health")
async def health():
    return {"status": "ok", "module": "crowdsec"}
