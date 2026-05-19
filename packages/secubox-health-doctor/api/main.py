#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: health-doctor FastAPI (issue #212)."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import checks, runner

app = FastAPI(
    title="SecuBox Health Doctor",
    description="Vital-services health monitor",
    version="1.0.0",
    root_path="/api/v1/health-doctor",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "secubox-health-doctor"}


@app.get("/checks")
def list_checks():
    """Read the persisted health state. CORS-open for the portal banner."""
    return JSONResponse(
        content=runner.current(),
        headers={"Cache-Control": "public, max-age=15"},
    )


@app.get("/status/{name}")
def status_of(name: str):
    if name not in checks.REGISTRY:
        raise HTTPException(status_code=404, detail=f"unknown check: {name}")
    state = runner.current()
    entry = state.get("checks", {}).get(name)
    if not entry:
        # Run on demand if not yet cached
        ok, details = checks.REGISTRY[name]()
        return {"name": name, "ok": ok, "details": details, "cached": False}
    return {"name": name, **entry, "cached": True}


@app.post("/run")
def run():
    """Trigger a fresh check pass. CORS POST allowed for admin UIs."""
    return runner.run_once()


@app.get("/registered")
def registered():
    """List all registered check names (for discovery)."""
    return {"checks": sorted(checks.REGISTRY.keys())}
