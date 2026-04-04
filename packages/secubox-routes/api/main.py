"""
SecuBox-Deb :: secubox-routes
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Routing table viewer and manager module.
Provides endpoints for viewing and managing IPv4/IPv6 routes,
policy routing rules, and ARP/NDP neighbors.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
import subprocess
import json
import re

app = FastAPI(
    title="secubox-routes",
    version="1.0.0",
    root_path="/api/v1/routes"
)
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("routes")


# ══════════════════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════════════════

class RouteEntry(BaseModel):
    """A single route entry."""
    destination: str
    gateway: Optional[str] = None
    interface: Optional[str] = None
    metric: Optional[int] = None
    protocol: Optional[str] = None
    scope: Optional[str] = None
    type: Optional[str] = None
    flags: List[str] = Field(default_factory=list)


class AddRouteRequest(BaseModel):
    """Request to add a route."""
    destination: str = Field(..., description="Destination network (e.g., 10.0.0.0/8)")
    gateway: Optional[str] = Field(None, description="Gateway IP address")
    interface: Optional[str] = Field(None, description="Output interface (e.g., eth0)")
    metric: Optional[int] = Field(None, description="Route metric/priority")
    table: Optional[str] = Field(None, description="Routing table name or ID")


class DeleteRouteRequest(BaseModel):
    """Request to delete a route."""
    destination: str = Field(..., description="Destination network to delete")
    gateway: Optional[str] = Field(None, description="Gateway (for specificity)")
    interface: Optional[str] = Field(None, description="Interface (for specificity)")
    table: Optional[str] = Field(None, description="Routing table name or ID")


class PolicyRule(BaseModel):
    """A policy routing rule."""
    priority: int
    selector: Optional[str] = None
    action: Optional[str] = None
    table: Optional[str] = None
    fwmark: Optional[str] = None
    iif: Optional[str] = None
    oif: Optional[str] = None


class AddRuleRequest(BaseModel):
    """Request to add a policy rule."""
    priority: int = Field(..., description="Rule priority (0-32767)")
    from_: Optional[str] = Field(None, alias="from", description="Source prefix")
    to: Optional[str] = Field(None, description="Destination prefix")
    table: Optional[str] = Field(None, description="Routing table to use")
    fwmark: Optional[str] = Field(None, description="Firewall mark")
    iif: Optional[str] = Field(None, description="Input interface")
    oif: Optional[str] = Field(None, description="Output interface")


class Neighbor(BaseModel):
    """ARP/NDP neighbor entry."""
    ip: str
    mac: Optional[str] = None
    interface: str
    state: str
    family: str  # inet or inet6


# ══════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════

def _run_ip(args: list, timeout: int = 10) -> dict:
    """Run ip command and return result."""
    cmd = ["ip", "-j"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip(), "data": []}

        # Parse JSON output
        output = result.stdout.strip()
        if not output:
            return {"success": True, "data": []}

        try:
            data = json.loads(output)
            return {"success": True, "data": data}
        except json.JSONDecodeError:
            # Some ip commands don't output valid JSON
            return {"success": True, "data": [], "raw": output}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out", "data": []}
    except Exception as e:
        return {"success": False, "error": str(e), "data": []}


def _run_ip_action(args: list, timeout: int = 10) -> dict:
    """Run ip command for add/delete actions (no JSON output)."""
    cmd = ["ip"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}
        return {"success": True, "message": "Operation completed"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _parse_routes(data: list, family: str) -> List[RouteEntry]:
    """Parse route data from ip -j route show."""
    routes = []
    for r in data:
        entry = RouteEntry(
            destination=r.get("dst", "default"),
            gateway=r.get("gateway"),
            interface=r.get("dev"),
            metric=r.get("metric"),
            protocol=r.get("protocol"),
            scope=r.get("scope"),
            type=r.get("type"),
            flags=r.get("flags", [])
        )
        routes.append(entry)
    return routes


def _parse_rules(data: list) -> List[PolicyRule]:
    """Parse policy rules from ip -j rule show."""
    rules = []
    for r in data:
        # Build selector string
        selectors = []
        if r.get("src"):
            selectors.append(f"from {r['src']}")
        if r.get("dst"):
            selectors.append(f"to {r['dst']}")
        if r.get("fwmark"):
            selectors.append(f"fwmark {r['fwmark']}")
        if r.get("iif"):
            selectors.append(f"iif {r['iif']}")
        if r.get("oif"):
            selectors.append(f"oif {r['oif']}")

        rule = PolicyRule(
            priority=r.get("priority", 0),
            selector=" ".join(selectors) if selectors else "all",
            action=r.get("action", "lookup"),
            table=r.get("table"),
            fwmark=r.get("fwmark"),
            iif=r.get("iif"),
            oif=r.get("oif")
        )
        rules.append(rule)
    return rules


def _parse_neighbors(data: list) -> List[Neighbor]:
    """Parse neighbor data from ip -j neigh show."""
    neighbors = []
    for n in data:
        # Determine family from IP address
        ip = n.get("dst", "")
        family = "inet6" if ":" in ip else "inet"

        entry = Neighbor(
            ip=ip,
            mac=n.get("lladdr"),
            interface=n.get("dev", ""),
            state=n.get("state", ["UNKNOWN"])[0] if isinstance(n.get("state"), list) else n.get("state", "UNKNOWN"),
            family=family
        )
        neighbors.append(entry)
    return neighbors


# ══════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════

@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get module status with route/rule/neighbor counts."""
    ipv4_result = _run_ip(["-4", "route", "show"])
    ipv6_result = _run_ip(["-6", "route", "show"])
    rules_result = _run_ip(["rule", "show"])
    neigh_result = _run_ip(["neigh", "show"])

    return {
        "module": "routes",
        "status": "running",
        "ipv4_routes": len(ipv4_result.get("data", [])),
        "ipv6_routes": len(ipv6_result.get("data", [])),
        "rules": len(rules_result.get("data", [])),
        "neighbors": len(neigh_result.get("data", []))
    }


@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    # Quick test: run ip route
    result = _run_ip(["-4", "route", "show", "default"])
    return {
        "status": "ok" if result.get("success") else "degraded",
        "module": "routes",
        "version": "1.0.0",
        "ip_command": result.get("success", False)
    }


@router.get("/routes")
async def get_all_routes(user=Depends(require_jwt)):
    """Get all routes (IPv4 and IPv6)."""
    ipv4_result = _run_ip(["-4", "route", "show"])
    ipv6_result = _run_ip(["-6", "route", "show"])

    ipv4_routes = _parse_routes(ipv4_result.get("data", []), "inet")
    ipv6_routes = _parse_routes(ipv6_result.get("data", []), "inet6")

    return {
        "ipv4": [r.model_dump() for r in ipv4_routes],
        "ipv6": [r.model_dump() for r in ipv6_routes],
        "total": len(ipv4_routes) + len(ipv6_routes)
    }


@router.get("/routes/ipv4")
async def get_ipv4_routes(table: Optional[str] = None, user=Depends(require_jwt)):
    """Get IPv4 routes."""
    args = ["-4", "route", "show"]
    if table:
        args.extend(["table", table])

    result = _run_ip(args)
    routes = _parse_routes(result.get("data", []), "inet")

    return {
        "routes": [r.model_dump() for r in routes],
        "count": len(routes),
        "table": table or "main"
    }


@router.get("/routes/ipv6")
async def get_ipv6_routes(table: Optional[str] = None, user=Depends(require_jwt)):
    """Get IPv6 routes."""
    args = ["-6", "route", "show"]
    if table:
        args.extend(["table", table])

    result = _run_ip(args)
    routes = _parse_routes(result.get("data", []), "inet6")

    return {
        "routes": [r.model_dump() for r in routes],
        "count": len(routes),
        "table": table or "main"
    }


@router.post("/routes")
async def add_route(req: AddRouteRequest, user=Depends(require_jwt)):
    """Add a new route."""
    args = ["route", "add", req.destination]

    if req.gateway:
        args.extend(["via", req.gateway])
    if req.interface:
        args.extend(["dev", req.interface])
    if req.metric is not None:
        args.extend(["metric", str(req.metric)])
    if req.table:
        args.extend(["table", req.table])

    log.info("Adding route: %s", " ".join(args))
    result = _run_ip_action(args)

    if result.get("success"):
        log.info("Route added: %s", req.destination)
    else:
        log.warning("Failed to add route: %s - %s", req.destination, result.get("error"))

    return result


@router.delete("/routes")
async def delete_route(req: DeleteRouteRequest, user=Depends(require_jwt)):
    """Delete a route."""
    args = ["route", "del", req.destination]

    if req.gateway:
        args.extend(["via", req.gateway])
    if req.interface:
        args.extend(["dev", req.interface])
    if req.table:
        args.extend(["table", req.table])

    log.info("Deleting route: %s", " ".join(args))
    result = _run_ip_action(args)

    if result.get("success"):
        log.info("Route deleted: %s", req.destination)
    else:
        log.warning("Failed to delete route: %s - %s", req.destination, result.get("error"))

    return result


@router.get("/tables")
async def get_tables(user=Depends(require_jwt)):
    """List routing tables."""
    tables = []

    # Read rt_tables file
    try:
        with open("/etc/iproute2/rt_tables", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    tables.append({
                        "id": int(parts[0]),
                        "name": parts[1]
                    })
    except FileNotFoundError:
        # Default tables
        tables = [
            {"id": 255, "name": "local"},
            {"id": 254, "name": "main"},
            {"id": 253, "name": "default"},
            {"id": 0, "name": "unspec"}
        ]
    except Exception as e:
        log.error("Failed to read rt_tables: %s", e)

    return {"tables": tables}


@router.get("/rules")
async def get_rules(user=Depends(require_jwt)):
    """Get policy routing rules."""
    ipv4_result = _run_ip(["-4", "rule", "show"])
    ipv6_result = _run_ip(["-6", "rule", "show"])

    ipv4_rules = _parse_rules(ipv4_result.get("data", []))
    ipv6_rules = _parse_rules(ipv6_result.get("data", []))

    return {
        "ipv4": [r.model_dump() for r in ipv4_rules],
        "ipv6": [r.model_dump() for r in ipv6_rules],
        "total": len(ipv4_rules) + len(ipv6_rules)
    }


@router.post("/rules")
async def add_rule(req: AddRuleRequest, user=Depends(require_jwt)):
    """Add a policy routing rule."""
    args = ["rule", "add", "priority", str(req.priority)]

    from_val = getattr(req, 'from_', None) or req.model_dump().get('from')
    if from_val:
        args.extend(["from", from_val])
    if req.to:
        args.extend(["to", req.to])
    if req.table:
        args.extend(["table", req.table])
    if req.fwmark:
        args.extend(["fwmark", req.fwmark])
    if req.iif:
        args.extend(["iif", req.iif])
    if req.oif:
        args.extend(["oif", req.oif])

    log.info("Adding rule: %s", " ".join(args))
    result = _run_ip_action(args)

    if result.get("success"):
        log.info("Rule added with priority %d", req.priority)
    else:
        log.warning("Failed to add rule: %s", result.get("error"))

    return result


@router.delete("/rules/{priority}")
async def delete_rule(priority: int, user=Depends(require_jwt)):
    """Delete a policy routing rule by priority."""
    args = ["rule", "del", "priority", str(priority)]

    log.info("Deleting rule with priority: %d", priority)
    result = _run_ip_action(args)

    if result.get("success"):
        log.info("Rule deleted: priority %d", priority)
    else:
        log.warning("Failed to delete rule: %s", result.get("error"))

    return result


@router.get("/neighbors")
async def get_neighbors(user=Depends(require_jwt)):
    """Get ARP/NDP neighbor table."""
    result = _run_ip(["neigh", "show"])
    neighbors = _parse_neighbors(result.get("data", []))

    # Separate by family
    arp = [n.model_dump() for n in neighbors if n.family == "inet"]
    ndp = [n.model_dump() for n in neighbors if n.family == "inet6"]

    return {
        "arp": arp,
        "ndp": ndp,
        "total": len(neighbors)
    }


@router.post("/flush")
async def flush_cache(user=Depends(require_jwt)):
    """Flush the route cache."""
    log.info("Flushing route cache")
    result = _run_ip_action(["route", "flush", "cache"])

    if result.get("success"):
        log.info("Route cache flushed")
    else:
        log.warning("Failed to flush cache: %s", result.get("error"))

    return result


# Include router
app.include_router(router)
