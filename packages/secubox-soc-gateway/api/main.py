"""
SecuBox-Deb :: SOC Gateway API
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Central SOC aggregation gateway for fleet monitoring.
Aggregates metrics from edge nodes, provides unified alerts, and enables remote management.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from secubox_core.auth import require_jwt

# Import gateway libraries
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.node_registry import NodeRegistry, NodeStatus
from lib.aggregator import aggregator
from lib.alert_correlator import correlator
from lib.remote_command import RemoteCommandManager
from lib.hierarchy import hierarchy, GatewayMode
from lib.cross_region_correlator import cross_region_correlator

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secubox.soc-gateway")

app = FastAPI(
    title="SecuBox SOC Gateway",
    description="Central SOC aggregation gateway for fleet monitoring",
    version="1.0.0"
)

# Initialize components
DATA_DIR = Path("/var/lib/secubox/soc-gateway")
registry = NodeRegistry(DATA_DIR)
command_manager = RemoteCommandManager(registry)

# WebSocket connections for real-time updates
websocket_clients: List[WebSocket] = []


# Models
class EnrollmentTokenRequest(BaseModel):
    ttl_minutes: int = 60
    region: str = ""
    tags: List[str] = []


class EnrollRequest(BaseModel):
    enrollment_token: str
    node_id: str
    hostname: str
    capabilities: List[str] = []


class CommandRequest(BaseModel):
    action: str
    args: List[str] = []


class BroadcastRequest(BaseModel):
    action: str
    args: List[str] = []
    node_ids: List[str] = None
    region: str = None


class HierarchyModeRequest(BaseModel):
    mode: str  # edge, regional, central
    region_id: str = ""
    region_name: str = ""


class RegionalTokenRequest(BaseModel):
    region_id: str
    region_name: str
    ttl_minutes: int = 1440


class RegionalEnrollRequest(BaseModel):
    enrollment_token: str
    region_id: str
    region_name: str


class CentralEnrollRequest(BaseModel):
    central_url: str
    enrollment_token: str


# ============================================================================
# Public Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Get gateway status."""
    summary = registry.get_fleet_summary()
    hierarchy_status = hierarchy.get_status()
    return {
        "module": "soc-gateway",
        "status": "ok",
        "version": "1.1.0",
        "mode": hierarchy_status.get("mode"),
        "region_id": hierarchy_status.get("region_id"),
        "region_name": hierarchy_status.get("region_name"),
        "fleet": summary,
        "hierarchy": hierarchy_status,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "module": "soc-gateway"}


# ============================================================================
# Node Enrollment (semi-public - requires enrollment token)
# ============================================================================

@app.post("/enroll")
async def enroll_node(request: EnrollRequest, req: Request):
    """Enroll a new edge node."""
    # Get client IP
    ip_address = req.client.host
    forwarded = req.headers.get("x-forwarded-for")
    if forwarded:
        ip_address = forwarded.split(",")[0].strip()

    result = registry.enroll_node(
        enrollment_token=request.enrollment_token,
        node_id=request.node_id,
        hostname=request.hostname,
        ip_address=ip_address,
        capabilities=request.capabilities
    )

    if result:
        logger.info(f"Node enrolled: {request.node_id}")
        return {
            "status": "enrolled",
            **result,
            "upstream_url": f"http://{req.headers.get('host', 'localhost')}/api/v1/soc-gateway"
        }

    raise HTTPException(status_code=400, detail="Invalid enrollment token")


@app.post("/ingest")
async def ingest_metrics(request: Request):
    """Receive metrics from an edge node (signed request)."""
    # Get node ID and signature from headers
    node_id = request.headers.get("X-Node-ID")
    signature = request.headers.get("X-Node-Signature")
    timestamp = request.headers.get("X-Node-Timestamp")

    if not node_id:
        raise HTTPException(status_code=400, detail="Missing X-Node-ID header")

    # Verify node exists
    node = registry.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not registered")

    # Parse body
    body = await request.body()
    try:
        metrics = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Update node metrics
    registry.update_node_metrics(node_id, metrics)

    # Aggregate metrics
    aggregator.ingest_metrics(
        node_id=node_id,
        hostname=node.hostname,
        metrics=metrics
    )

    # Process alerts for correlation
    alerts = metrics.get("alerts", [])
    if alerts:
        correlator.process_alerts(node_id, alerts)

    # Broadcast to WebSocket clients
    await broadcast_update({
        "type": "metrics",
        "node_id": node_id,
        "health": metrics.get("health"),
        "timestamp": timestamp
    })

    return {"status": "accepted", "node_id": node_id}


# ============================================================================
# Fleet Overview (Protected)
# ============================================================================

@app.get("/fleet/summary", dependencies=[Depends(require_jwt)])
async def get_fleet_summary():
    """Get fleet-wide summary statistics."""
    return aggregator.get_fleet_summary()


@app.get("/fleet/nodes", dependencies=[Depends(require_jwt)])
async def get_fleet_nodes(
    status: Optional[str] = None,
    region: Optional[str] = None
):
    """Get all registered nodes."""
    nodes = registry.get_all_nodes(status=status, region=region)
    return {
        "nodes": [
            {
                "node_id": n.node_id,
                "hostname": n.hostname,
                "status": n.status,
                "health": n.health,
                "ip_address": n.ip_address,
                "region": n.region,
                "last_seen": n.last_seen,
                "enrolled_at": n.enrolled_at
            }
            for n in nodes
        ],
        "count": len(nodes)
    }


@app.get("/fleet/nodes/{node_id}", dependencies=[Depends(require_jwt)])
async def get_node_detail(node_id: str):
    """Get detailed information for a specific node."""
    node = registry.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    detail = aggregator.get_node_detail(node_id)
    return {
        "node": {
            "node_id": node.node_id,
            "hostname": node.hostname,
            "status": node.status,
            "health": node.health,
            "ip_address": node.ip_address,
            "region": node.region,
            "tags": node.tags,
            "capabilities": node.capabilities,
            "enrolled_at": node.enrolled_at,
            "last_seen": node.last_seen
        },
        "metrics": detail.get("metrics") if detail else None,
        "alerts": detail.get("alerts", []) if detail else []
    }


@app.delete("/fleet/nodes/{node_id}", dependencies=[Depends(require_jwt)])
async def delete_node(node_id: str):
    """Delete a node from the registry."""
    if registry.delete_node(node_id):
        return {"status": "deleted", "node_id": node_id}
    raise HTTPException(status_code=404, detail="Node not found")


# ============================================================================
# Alerts (Protected)
# ============================================================================

@app.get("/alerts/stream", dependencies=[Depends(require_jwt)])
async def get_alerts(
    limit: int = 50,
    source: Optional[str] = None,
    node_id: Optional[str] = None,
    severity: Optional[str] = None
):
    """Get unified alert stream from all nodes."""
    alerts = aggregator.get_alerts(
        limit=limit,
        source=source,
        node_id=node_id,
        severity=severity
    )
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/alerts/correlated", dependencies=[Depends(require_jwt)])
async def get_correlated_threats(
    severity: Optional[str] = None,
    min_nodes: int = 2
):
    """Get cross-node correlated threats."""
    threats = correlator.get_correlated_threats(
        severity=severity,
        min_nodes=min_nodes
    )
    return {"threats": threats, "count": len(threats)}


@app.get("/alerts/correlation-summary", dependencies=[Depends(require_jwt)])
async def get_correlation_summary():
    """Get threat correlation summary."""
    return correlator.get_threat_summary()


# ============================================================================
# Remote Commands (Protected)
# ============================================================================

@app.post("/nodes/{node_id}/command", dependencies=[Depends(require_jwt)])
async def send_command(node_id: str, request: CommandRequest):
    """Send a command to a specific node."""
    try:
        cmd = command_manager.create_command(
            node_id=node_id,
            action=request.action,
            args=request.args
        )
        return {
            "command_id": cmd.id,
            "status": "queued",
            "node_id": node_id,
            "action": request.action
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/nodes/{node_id}/services/{service}/action", dependencies=[Depends(require_jwt)])
async def service_action(node_id: str, service: str, action: str):
    """Perform an action on a service on a remote node."""
    valid_actions = ["start", "stop", "restart", "status"]
    if action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Invalid action. Use: {valid_actions}")

    try:
        cmd = command_manager.create_command(
            node_id=node_id,
            action=f"service.{action}",
            args=[service]
        )
        return {
            "command_id": cmd.id,
            "status": "queued",
            "node_id": node_id,
            "service": service,
            "action": action
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/broadcast", dependencies=[Depends(require_jwt)])
async def broadcast_command(request: BroadcastRequest):
    """Broadcast a command to multiple nodes."""
    result = await command_manager.broadcast_command(
        action=request.action,
        args=request.args,
        node_ids=request.node_ids,
        region=request.region
    )
    return result


@app.get("/commands", dependencies=[Depends(require_jwt)])
async def get_commands(
    node_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50
):
    """Get command history."""
    commands = command_manager.get_commands(
        node_id=node_id,
        status=status,
        limit=limit
    )
    return {"commands": commands, "count": len(commands)}


@app.get("/commands/{cmd_id}", dependencies=[Depends(require_jwt)])
async def get_command(cmd_id: str):
    """Get command details."""
    cmd = command_manager.get_command(cmd_id)
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")
    return cmd


# ============================================================================
# Enrollment Tokens (Protected)
# ============================================================================

@app.post("/tokens", dependencies=[Depends(require_jwt)])
async def generate_enrollment_token(request: EnrollmentTokenRequest):
    """Generate a new enrollment token for edge nodes."""
    token = registry.generate_enrollment_token(
        ttl_minutes=request.ttl_minutes,
        region=request.region,
        tags=request.tags
    )
    return token


@app.post("/tokens/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_tokens():
    """Remove expired enrollment tokens."""
    count = registry.cleanup_stale_tokens()
    return {"cleaned": count}


# ============================================================================
# WebSocket for Real-Time Updates
# ============================================================================

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert streaming."""
    await websocket.accept()
    websocket_clients.append(websocket)

    try:
        while True:
            # Wait for messages from client (heartbeat)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        websocket_clients.remove(websocket)
    except Exception:
        if websocket in websocket_clients:
            websocket_clients.remove(websocket)


async def broadcast_update(data: dict):
    """Broadcast update to all WebSocket clients."""
    message = json.dumps(data)
    disconnected = []

    for client in websocket_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        websocket_clients.remove(client)


# ============================================================================
# Hierarchical Mode (Protected)
# ============================================================================

@app.get("/hierarchy/status", dependencies=[Depends(require_jwt)])
async def get_hierarchy_status():
    """Get hierarchical mode status."""
    return hierarchy.get_status()


@app.post("/hierarchy/mode", dependencies=[Depends(require_jwt)])
async def set_hierarchy_mode(request: HierarchyModeRequest):
    """Set gateway hierarchical mode."""
    try:
        mode = GatewayMode(request.mode)
        hierarchy.set_mode(mode, request.region_id, request.region_name)
        return {"status": "updated", "mode": mode.value}
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid mode. Use: edge, regional, central")


# ============================================================================
# Central SOC Endpoints (for regional SOC management)
# ============================================================================

@app.post("/regional/token", dependencies=[Depends(require_jwt)])
async def generate_regional_token(request: RegionalTokenRequest):
    """Generate enrollment token for a regional SOC (central mode only)."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC can generate regional tokens")

    try:
        token = hierarchy.generate_regional_token(
            region_id=request.region_id,
            region_name=request.region_name,
            ttl_minutes=request.ttl_minutes
        )
        return token
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/regional/enroll")
async def enroll_regional_soc(request: RegionalEnrollRequest, req: Request):
    """Enroll a regional SOC with this central."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC can enroll regional SOCs")

    # Get client IP
    ip_address = req.client.host
    forwarded = req.headers.get("x-forwarded-for")
    if forwarded:
        ip_address = forwarded.split(",")[0].strip()

    result = hierarchy.enroll_regional_soc(
        enrollment_token=request.enrollment_token,
        region_id=request.region_id,
        region_name=request.region_name,
        ip_address=ip_address
    )

    if result:
        logger.info(f"Regional SOC enrolled: {request.region_id}")
        return {"status": "enrolled", **result}

    raise HTTPException(status_code=400, detail="Invalid enrollment token")


@app.post("/regional/ingest")
async def ingest_regional_data(request: Request):
    """Receive aggregated data from a regional SOC."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC accepts regional data")

    # Get region ID and validate
    region_id = request.headers.get("X-Region-ID")
    if not region_id:
        raise HTTPException(status_code=400, detail="Missing X-Region-ID header")

    # Verify region is registered
    regional_socs = hierarchy.get_regional_socs()
    region_data = next((r for r in regional_socs if r.get("region_id") == region_id), None)

    if not region_data:
        raise HTTPException(status_code=404, detail="Regional SOC not registered")

    # Parse body
    body = await request.body()
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Update regional metrics
    hierarchy.update_regional_metrics(region_id, data)

    # Process for cross-region correlation
    cross_region_correlator.ingest_regional_data(
        region_id=region_id,
        region_name=region_data.get("region_name", region_id),
        data=data
    )

    # Broadcast to WebSocket clients
    await broadcast_update({
        "type": "regional_update",
        "region_id": region_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })

    return {"status": "accepted", "region_id": region_id}


@app.get("/regional/socs", dependencies=[Depends(require_jwt)])
async def get_regional_socs():
    """Get all registered regional SOCs (central mode only)."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC has regional SOCs")

    return {
        "regional_socs": hierarchy.get_regional_socs(),
        "count": len(hierarchy.get_regional_socs())
    }


# ============================================================================
# Regional SOC Endpoints (for connecting to central)
# ============================================================================

@app.post("/upstream/enroll", dependencies=[Depends(require_jwt)])
async def enroll_with_central(request: CentralEnrollRequest):
    """Enroll this regional SOC with a central SOC."""
    if not hierarchy.is_regional():
        raise HTTPException(status_code=403, detail="Only regional SOC can enroll with central")

    result = await hierarchy.enroll_with_central(
        central_url=request.central_url,
        enrollment_token=request.enrollment_token
    )

    if result.get("status") == "enrolled":
        # Start upstream push
        async def get_aggregated():
            summary = aggregator.get_fleet_summary()
            threats = correlator.get_correlated_threats()
            return {
                "region": hierarchy.config.region_id,
                "region_name": hierarchy.config.region_name,
                "nodes_online": summary.get("nodes_online", 0),
                "nodes_total": summary.get("nodes_total", 0),
                "alerts_count": len(aggregator.get_alerts(limit=1000)),
                "critical_alerts": summary.get("by_health", {}).get("critical", 0),
                "correlated_threats": threats,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

        hierarchy.start_upstream_push(get_aggregated)
        return result

    raise HTTPException(status_code=400, detail=result.get("message", "Enrollment failed"))


@app.get("/upstream/status", dependencies=[Depends(require_jwt)])
async def get_upstream_status():
    """Get upstream connection status (regional mode only)."""
    if not hierarchy.is_regional():
        return {"status": "not_regional_mode"}

    return {
        "connected": hierarchy.has_upstream(),
        "upstream_url": hierarchy.config.upstream_url or None,
        "region_id": hierarchy.config.region_id,
        "region_name": hierarchy.config.region_name
    }


# ============================================================================
# Cross-Region Threats (Central Mode)
# ============================================================================

@app.get("/global/summary", dependencies=[Depends(require_jwt)])
async def get_global_summary():
    """Get global cross-region summary (central mode only)."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC has global view")

    return cross_region_correlator.get_global_summary()


@app.get("/global/regions", dependencies=[Depends(require_jwt)])
async def get_regional_breakdown():
    """Get breakdown by region (central mode only)."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC has global view")

    return {
        "regions": cross_region_correlator.get_regional_breakdown(),
        "count": len(cross_region_correlator.regional_summaries)
    }


@app.get("/global/threats", dependencies=[Depends(require_jwt)])
async def get_cross_region_threats(
    severity: Optional[str] = None,
    min_regions: int = 2
):
    """Get cross-region correlated threats (central mode only)."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC has global view")

    threats = cross_region_correlator.get_cross_region_threats(
        severity=severity,
        min_regions=min_regions
    )
    return {"threats": threats, "count": len(threats)}


@app.post("/global/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_cross_region(hours: int = 48):
    """Cleanup stale cross-region threat data."""
    if not hierarchy.is_central():
        raise HTTPException(status_code=403, detail="Only central SOC can cleanup")

    count = cross_region_correlator.cleanup_stale(hours)
    return {"cleaned": count}


# ============================================================================
# Lifecycle
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize gateway on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    registry.update_status()
    registry.cleanup_stale_tokens()

    # Start upstream push if in regional mode with upstream configured
    if hierarchy.is_regional() and hierarchy.has_upstream():
        async def get_aggregated():
            summary = aggregator.get_fleet_summary()
            threats = correlator.get_correlated_threats()
            return {
                "region": hierarchy.config.region_id,
                "region_name": hierarchy.config.region_name,
                "nodes_online": summary.get("nodes_online", 0),
                "nodes_total": summary.get("nodes_total", 0),
                "alerts_count": len(aggregator.get_alerts(limit=1000)),
                "critical_alerts": summary.get("by_health", {}).get("critical", 0),
                "correlated_threats": threats,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

        hierarchy.start_upstream_push(get_aggregated)
        logger.info(f"Regional mode: upstream push started to {hierarchy.config.upstream_url}")

    logger.info(f"SOC Gateway started (mode: {hierarchy.get_mode().value})")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    hierarchy.stop_upstream_push()
    aggregator.persist_cache()
    logger.info("SOC Gateway stopped")
