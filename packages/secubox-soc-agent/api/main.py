"""
SecuBox-Deb :: SOC Agent API
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Edge node agent for SOC integration.
Collects metrics, pushes to upstream SOC, receives remote commands.
"""

import logging
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel

from secubox_core.auth import require_jwt

# Import agent libraries
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.collector import (
    collect_metrics, collect_alerts, collect_full_report,
    get_machine_id, get_hostname
)
from lib.upstreamer import (
    config as upstreamer_config,
    enroll_with_gateway, push_metrics, test_connection,
    start_upstreamer, stop_upstreamer, get_status as get_upstream_status
)
from lib.command_handler import (
    Command, execute_command, get_allowed_actions, get_audit_log
)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secubox.soc-agent")

app = FastAPI(
    title="SecuBox SOC Agent",
    description="Edge node agent for SOC integration",
    version="1.0.0"
)


# Models
class EnrollRequest(BaseModel):
    gateway_url: str
    enrollment_token: str


class CommandRequest(BaseModel):
    id: str
    action: str
    args: List[str] = []
    signature: str
    from_node: Optional[str] = None


class ConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    interval: Optional[int] = None
    verify_ssl: Optional[bool] = None


# ============================================================================
# Public Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Get agent status."""
    upstream = get_upstream_status()
    return {
        "module": "soc-agent",
        "status": "ok",
        "version": "1.0.0",
        "node_id": get_machine_id(),
        "hostname": get_hostname(),
        "upstream": upstream,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "module": "soc-agent"}


@app.get("/metrics")
async def get_metrics():
    """Get current node metrics."""
    metrics = await collect_metrics()
    return metrics


@app.get("/alerts")
async def get_alerts():
    """Get current security alerts."""
    alerts = await collect_alerts()
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/report")
async def get_report():
    """Get full node report (metrics + alerts)."""
    report = await collect_full_report()
    return report


# ============================================================================
# Command Reception (from SOC Gateway)
# ============================================================================

@app.post("/command")
async def receive_command(cmd: CommandRequest, request: Request):
    """Receive and execute a command from SOC gateway."""
    # Verify request comes from registered upstream
    if not upstreamer_config.node_token:
        raise HTTPException(status_code=403, detail="Not enrolled with SOC")

    # Create command object
    command = Command(
        cmd_id=cmd.id,
        action=cmd.action,
        args=cmd.args,
        from_node=cmd.from_node,
        signature=cmd.signature
    )

    # Execute with validation
    result = await execute_command(command, upstreamer_config.node_token)
    return result


@app.get("/command/allowed")
async def get_allowed_commands():
    """Get list of allowed remote commands."""
    return get_allowed_actions()


# ============================================================================
# Protected Endpoints (require local JWT)
# ============================================================================

@app.post("/enroll", dependencies=[Depends(require_jwt)])
async def enroll(request: EnrollRequest):
    """Enroll this node with a SOC gateway."""
    result = await enroll_with_gateway(
        request.gateway_url,
        request.enrollment_token
    )

    if result.get("status") == "enrolled":
        # Start upstreamer
        start_upstreamer()

    return result


@app.post("/unenroll", dependencies=[Depends(require_jwt)])
async def unenroll():
    """Unenroll from SOC gateway."""
    stop_upstreamer()

    # Clear token
    token_file = Path("/var/lib/secubox/soc-agent/node_token")
    if token_file.exists():
        token_file.unlink()

    upstreamer_config.enabled = False
    upstreamer_config.node_token = ""
    upstreamer_config.upstream_url = ""
    upstreamer_config.save()

    return {"status": "unenrolled"}


@app.get("/upstream/status", dependencies=[Depends(require_jwt)])
async def upstream_status():
    """Get upstream connection status."""
    return get_upstream_status()


@app.post("/upstream/test", dependencies=[Depends(require_jwt)])
async def test_upstream():
    """Test connection to upstream SOC."""
    result = await test_connection()
    return result


@app.post("/upstream/push", dependencies=[Depends(require_jwt)])
async def manual_push():
    """Manually trigger metrics push."""
    result = await push_metrics()
    return result


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(config: ConfigUpdate):
    """Update agent configuration."""
    if config.enabled is not None:
        upstreamer_config.enabled = config.enabled
    if config.interval is not None:
        upstreamer_config.interval = max(30, min(config.interval, 600))
    if config.verify_ssl is not None:
        upstreamer_config.verify_ssl = config.verify_ssl

    upstreamer_config.save()
    return {"status": "updated", "config": {
        "enabled": upstreamer_config.enabled,
        "interval": upstreamer_config.interval,
        "verify_ssl": upstreamer_config.verify_ssl
    }}


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config():
    """Get current agent configuration."""
    return {
        "enabled": upstreamer_config.enabled,
        "upstream_url": upstreamer_config.upstream_url,
        "interval": upstreamer_config.interval,
        "timeout": upstreamer_config.timeout,
        "verify_ssl": upstreamer_config.verify_ssl,
        "enrolled": bool(upstreamer_config.node_token)
    }


@app.get("/audit", dependencies=[Depends(require_jwt)])
async def get_audit(limit: int = 50):
    """Get command audit log."""
    entries = get_audit_log(limit)
    return {"entries": entries, "count": len(entries)}


# ============================================================================
# Lifecycle
# ============================================================================

@app.on_event("startup")
async def startup():
    """Start agent on API startup."""
    logger.info("SOC Agent starting")
    upstreamer_config.load()

    if upstreamer_config.enabled and upstreamer_config.node_token:
        start_upstreamer()
        logger.info("Upstreamer started (enrolled)")
    else:
        logger.info("Upstreamer not started (not enrolled)")


@app.on_event("shutdown")
async def shutdown():
    """Stop agent on API shutdown."""
    stop_upstreamer()
    logger.info("SOC Agent stopped")
