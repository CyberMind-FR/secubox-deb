"""
secubox-crowdsec — FastAPI application
Port de luci-app-crowdsec-dashboard vers Debian

RPCD source : luci.crowdsec-dashboard
Méthodes complètes : status, decisions, alerts, bouncers, metrics, machines,
           hub, collections, wizard, console, acquisition, settings, etc.

Three-fold architecture:
  - /components : what is this module made of
  - /status     : health and runtime state
  - /access     : how to connect
"""
import asyncio
import subprocess
import json
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

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

log = get_logger("crowdsec")

app = FastAPI(
    title="secubox-crowdsec",
    version="1.0.2",
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


# === Helper: run crowdsecctl ===
async def _run_ctl(*args, timeout: int = 30) -> dict:
    """Run crowdsecctl and return JSON output."""
    cmd = ["/usr/sbin/crowdsecctl"] + list(args)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode().strip()
        if proc.returncode == 0 and output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return {"output": output, "success": True}
        return {"success": proc.returncode == 0, "output": output, "error": stderr.decode().strip()}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        log.error("crowdsecctl error: %s", e)
        return {"success": False, "error": str(e)}


# === Three-Fold Architecture Endpoints ===

@app.get("/components")
async def components():
    """List system components (public, three-fold: what)."""
    return {
        "components": [
            {
                "name": "CrowdSec Engine",
                "type": "service",
                "description": "Security automation engine with behavior detection",
                "package": "crowdsec",
                "service": "crowdsec.service",
            },
            {
                "name": "CrowdSec LAPI",
                "type": "api",
                "description": "Local API for decision management and bouncer communication",
                "port": 8080,
                "protocol": "http",
            },
            {
                "name": "Firewall Bouncer",
                "type": "service",
                "description": "nftables bouncer for IP blocking",
                "package": "crowdsec-firewall-bouncer-nftables",
                "service": "crowdsec-firewall-bouncer.service",
            },
            {
                "name": "Hub Collections",
                "type": "content",
                "description": "Scenarios, parsers, and postoverflows from CrowdSec Hub",
                "path": "/etc/crowdsec/hub",
            },
            {
                "name": "crowdsecctl",
                "type": "cli",
                "description": "SecuBox CrowdSec control interface",
                "path": "/usr/sbin/crowdsecctl",
            },
        ]
    }


@app.get("/access")
async def access():
    """Show connection endpoints (public, three-fold: how)."""
    import socket
    hostname = socket.getfqdn()

    return {
        "endpoints": [
            {
                "name": "CrowdSec Dashboard",
                "url": f"https://{hostname}/crowdsec/",
                "description": "SecuBox CrowdSec management interface",
            },
            {
                "name": "LAPI (Local)",
                "url": "http://127.0.0.1:8080",
                "description": "Local API for bouncers and decisions",
                "internal": True,
            },
            {
                "name": "Prometheus Metrics",
                "url": "http://127.0.0.1:6060/metrics",
                "description": "CrowdSec metrics endpoint",
                "internal": True,
            },
        ],
        "cli": {
            "tool": "cscli",
            "examples": [
                "cscli decisions list",
                "cscli alerts list",
                "cscli bouncers list",
                "cscli hub list",
            ],
        },
        "documentation": "https://docs.crowdsec.net/",
    }


# === Migration Endpoint ===

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"
    dry_run: bool = False


@app.post("/migrate")
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Migrate CrowdSec configuration from OpenWrt."""
    log.info("Migration requested from %s (dry_run=%s)", req.source, req.dry_run)

    args = ["migrate", req.source]
    if req.dry_run:
        args.append("--dry-run")

    # Run migration in background for long-running operation
    result = await _run_ctl(*args, timeout=120)
    return result


# === nftables Statistics ===

@app.get("/nftables")
async def nftables_stats(user=Depends(require_jwt)):
    """Get nftables CrowdSec statistics."""
    return await _run_ctl("nftables")


# === Service Control ===

@app.post("/service/start")
async def service_start(user=Depends(require_jwt)):
    """Start CrowdSec services."""
    log.info("Starting CrowdSec services")
    return await _run_ctl("start")


@app.post("/service/stop")
async def service_stop(user=Depends(require_jwt)):
    """Stop CrowdSec services."""
    log.info("Stopping CrowdSec services")
    return await _run_ctl("stop")


@app.post("/service/restart")
async def service_restart(user=Depends(require_jwt)):
    """Restart CrowdSec services."""
    log.info("Restarting CrowdSec services")
    return await _run_ctl("restart")


# === Console Management ===

class ConsoleEnrollRequest(BaseModel):
    enrollment_key: str


@app.get("/console/status")
async def console_status(user=Depends(require_jwt)):
    """Check CrowdSec Console connection status."""
    return await _run_ctl("console", "status")


@app.post("/console/enroll")
async def console_enroll(req: ConsoleEnrollRequest, user=Depends(require_jwt)):
    """Enroll to CrowdSec Console."""
    log.info("Enrolling to CrowdSec Console")
    return await _run_ctl("console", "enroll", req.enrollment_key)


# === Debug ===

@app.get("/debug")
async def debug_info(user=Depends(require_jwt)):
    """Collect debug information."""
    return await _run_ctl("debug")


# === Health Check ===

@app.get("/health")
async def health():
    """Health check endpoint."""
    # Quick check if CrowdSec is running
    try:
        result = subprocess.run(["pgrep", "crowdsec"], capture_output=True, timeout=2)
        running = result.returncode == 0
    except Exception:
        running = False

    return {
        "status": "ok" if running else "degraded",
        "module": "crowdsec",
        "engine_running": running,
    }
