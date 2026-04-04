"""
SecuBox-Deb :: secubox-metacatalog
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Service catalog and registry module.
Provides endpoints for discovering installed SecuBox services,
health status tracking, dependency mapping, and API documentation.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
import subprocess
import json
import asyncio
from pathlib import Path
from datetime import datetime

app = FastAPI(
    title="secubox-metacatalog",
    version="1.0.0",
    root_path="/api/v1/metacatalog"
)
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("metacatalog")

# Cache for service catalog
CACHE_FILE = Path("/var/cache/secubox/metacatalog/catalog.json")
_cache: Dict[str, Any] = {}
_last_refresh: Optional[datetime] = None


# ======================================================================
# Pydantic Models
# ======================================================================

class ServiceEndpoint(BaseModel):
    """An API endpoint of a service."""
    method: str
    path: str
    description: Optional[str] = None
    auth_required: bool = True


class ServiceInfo(BaseModel):
    """Information about a SecuBox service."""
    name: str
    version: str = "1.0.0"
    description: Optional[str] = None
    status: str = "unknown"  # running, stopped, failed, unknown
    socket: Optional[str] = None
    port: Optional[int] = None
    category: str = "system"
    icon: Optional[str] = None
    menu_path: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    dependents: List[str] = Field(default_factory=list)
    endpoints: List[ServiceEndpoint] = Field(default_factory=list)
    systemd_unit: Optional[str] = None
    installed: bool = False
    enabled: bool = False
    active_since: Optional[str] = None
    memory_usage: Optional[str] = None


class CatalogStats(BaseModel):
    """Overall catalog statistics."""
    total_services: int = 0
    running: int = 0
    stopped: int = 0
    failed: int = 0
    unknown: int = 0
    last_refresh: Optional[str] = None


class DependencyGraph(BaseModel):
    """Service dependency graph."""
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, str]] = Field(default_factory=list)


# ======================================================================
# Service Discovery Functions
# ======================================================================

# Known SecuBox services with their metadata
KNOWN_SERVICES = {
    "secubox-core": {
        "description": "Core library and authentication service",
        "category": "system",
        "icon": "core",
        "dependencies": [],
    },
    "secubox-hub": {
        "description": "Central dashboard and monitoring hub",
        "category": "system",
        "icon": "hub",
        "dependencies": ["secubox-core"],
    },
    "secubox-crowdsec": {
        "description": "CrowdSec threat intelligence integration",
        "category": "security",
        "icon": "shield",
        "dependencies": ["secubox-core"],
    },
    "secubox-wireguard": {
        "description": "WireGuard VPN management",
        "category": "network",
        "icon": "vpn",
        "dependencies": ["secubox-core"],
    },
    "secubox-netdata": {
        "description": "Real-time performance monitoring",
        "category": "monitoring",
        "icon": "chart",
        "dependencies": ["secubox-core"],
    },
    "secubox-dpi": {
        "description": "Deep packet inspection with netifyd/nDPId",
        "category": "security",
        "icon": "inspect",
        "dependencies": ["secubox-core"],
    },
    "secubox-mediaflow": {
        "description": "Media flow monitoring and control",
        "category": "network",
        "icon": "media",
        "dependencies": ["secubox-core", "secubox-dpi"],
    },
    "secubox-qos": {
        "description": "Quality of Service / bandwidth management",
        "category": "network",
        "icon": "qos",
        "dependencies": ["secubox-core"],
    },
    "secubox-nac": {
        "description": "Network Access Control (client guardian)",
        "category": "security",
        "icon": "lock",
        "dependencies": ["secubox-core"],
    },
    "secubox-auth": {
        "description": "Authentication guardian (OAuth2/OIDC)",
        "category": "security",
        "icon": "key",
        "dependencies": ["secubox-core"],
    },
    "secubox-vhost": {
        "description": "Virtual host management",
        "category": "network",
        "icon": "server",
        "dependencies": ["secubox-core"],
    },
    "secubox-cdn": {
        "description": "CDN cache management",
        "category": "network",
        "icon": "cache",
        "dependencies": ["secubox-core"],
    },
    "secubox-netmodes": {
        "description": "Network modes configuration",
        "category": "network",
        "icon": "network",
        "dependencies": ["secubox-core"],
    },
    "secubox-system": {
        "description": "System management hub",
        "category": "system",
        "icon": "settings",
        "dependencies": ["secubox-core"],
    },
    "secubox-routes": {
        "description": "Routing table viewer and manager",
        "category": "network",
        "icon": "routes",
        "dependencies": ["secubox-core"],
    },
    "secubox-glances": {
        "description": "System monitoring with Glances",
        "category": "monitoring",
        "icon": "monitor",
        "dependencies": ["secubox-core"],
    },
    "secubox-netdiag": {
        "description": "Network diagnostics tools",
        "category": "network",
        "icon": "diag",
        "dependencies": ["secubox-core"],
    },
    "secubox-turn": {
        "description": "TURN/STUN server management",
        "category": "network",
        "icon": "turn",
        "dependencies": ["secubox-core"],
    },
    "secubox-mqtt": {
        "description": "MQTT broker management",
        "category": "network",
        "icon": "mqtt",
        "dependencies": ["secubox-core"],
    },
    "secubox-rtty": {
        "description": "Remote TTY access",
        "category": "system",
        "icon": "terminal",
        "dependencies": ["secubox-core"],
    },
    "secubox-smtp-relay": {
        "description": "SMTP relay configuration",
        "category": "network",
        "icon": "mail",
        "dependencies": ["secubox-core"],
    },
    "secubox-reporter": {
        "description": "Reporting and analytics",
        "category": "monitoring",
        "icon": "report",
        "dependencies": ["secubox-core"],
    },
    "secubox-metacatalog": {
        "description": "Service catalog and registry",
        "category": "system",
        "icon": "catalog",
        "dependencies": ["secubox-core"],
    },
}


def _run_systemctl(args: List[str], timeout: int = 10) -> Dict[str, Any]:
    """Run systemctl command and return result."""
    cmd = ["systemctl"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out", "stdout": "", "stderr": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "stdout": "", "stderr": ""}


def _get_service_status(service_name: str) -> Dict[str, Any]:
    """Get status of a systemd service."""
    unit_name = f"{service_name}.service"

    # Check if service is installed (unit file exists)
    result = _run_systemctl(["cat", unit_name])
    if not result.get("success"):
        return {
            "installed": False,
            "enabled": False,
            "status": "not_installed",
            "active_since": None,
            "memory_usage": None
        }

    # Check if enabled
    result = _run_systemctl(["is-enabled", unit_name])
    enabled = result.get("stdout") == "enabled"

    # Check if active
    result = _run_systemctl(["is-active", unit_name])
    active_state = result.get("stdout", "unknown")

    status = "unknown"
    if active_state == "active":
        status = "running"
    elif active_state == "inactive":
        status = "stopped"
    elif active_state == "failed":
        status = "failed"

    # Get detailed status
    active_since = None
    memory_usage = None

    if status == "running":
        # Get ActiveEnterTimestamp
        result = _run_systemctl(["show", unit_name, "-p", "ActiveEnterTimestamp", "--value"])
        if result.get("success") and result.get("stdout"):
            active_since = result.get("stdout")

        # Get MemoryCurrent
        result = _run_systemctl(["show", unit_name, "-p", "MemoryCurrent", "--value"])
        if result.get("success") and result.get("stdout"):
            mem_bytes = result.get("stdout")
            if mem_bytes and mem_bytes != "[not set]":
                try:
                    mem_val = int(mem_bytes)
                    if mem_val >= 1024 * 1024 * 1024:
                        memory_usage = f"{mem_val / (1024*1024*1024):.1f} GB"
                    elif mem_val >= 1024 * 1024:
                        memory_usage = f"{mem_val / (1024*1024):.1f} MB"
                    elif mem_val >= 1024:
                        memory_usage = f"{mem_val / 1024:.1f} KB"
                    else:
                        memory_usage = f"{mem_val} B"
                except ValueError:
                    pass

    return {
        "installed": True,
        "enabled": enabled,
        "status": status,
        "active_since": active_since,
        "memory_usage": memory_usage
    }


def _load_menu_entry(service_name: str) -> Dict[str, Any]:
    """Load menu.d entry for a service."""
    menu_dir = Path("/usr/share/secubox/menu.d")
    menu_info = {"icon": None, "menu_path": None, "category": "system"}

    try:
        for menu_file in menu_dir.glob("*.json"):
            try:
                data = json.loads(menu_file.read_text())
                # Check if this menu entry matches the service
                menu_id = data.get("id", "")
                if menu_id and service_name.endswith(menu_id):
                    menu_info["icon"] = data.get("icon")
                    menu_info["menu_path"] = data.get("path")
                    menu_info["category"] = data.get("category", "system")
                    break
            except (json.JSONDecodeError, IOError):
                continue
    except Exception as e:
        log.debug("Error loading menu entries: %s", e)

    return menu_info


def _discover_services() -> List[ServiceInfo]:
    """Discover all installed SecuBox services."""
    services = []

    for name, meta in KNOWN_SERVICES.items():
        status_info = _get_service_status(name)
        menu_info = _load_menu_entry(name)

        # Build dependency graph (who depends on this service)
        dependents = []
        for other_name, other_meta in KNOWN_SERVICES.items():
            if name in other_meta.get("dependencies", []):
                dependents.append(other_name)

        service = ServiceInfo(
            name=name,
            description=meta.get("description"),
            status=status_info["status"],
            socket=f"/run/secubox/{name.replace('secubox-', '')}.sock" if status_info["installed"] else None,
            category=menu_info.get("category") or meta.get("category", "system"),
            icon=menu_info.get("icon") or meta.get("icon"),
            menu_path=menu_info.get("menu_path"),
            dependencies=meta.get("dependencies", []),
            dependents=dependents,
            systemd_unit=f"{name}.service",
            installed=status_info["installed"],
            enabled=status_info["enabled"],
            active_since=status_info["active_since"],
            memory_usage=status_info["memory_usage"]
        )
        services.append(service)

    return services


def _build_dependency_graph(services: List[ServiceInfo]) -> DependencyGraph:
    """Build a dependency graph from services."""
    nodes = []
    edges = []

    for svc in services:
        nodes.append({
            "id": svc.name,
            "label": svc.name.replace("secubox-", ""),
            "status": svc.status,
            "category": svc.category,
            "installed": svc.installed
        })

        for dep in svc.dependencies:
            edges.append({
                "from": dep,
                "to": svc.name
            })

    return DependencyGraph(nodes=nodes, edges=edges)


async def _refresh_catalog() -> Dict[str, Any]:
    """Refresh the service catalog."""
    global _cache, _last_refresh

    try:
        services = _discover_services()

        stats = CatalogStats(
            total_services=len(services),
            running=len([s for s in services if s.status == "running"]),
            stopped=len([s for s in services if s.status == "stopped"]),
            failed=len([s for s in services if s.status == "failed"]),
            unknown=len([s for s in services if s.status in ("unknown", "not_installed")]),
            last_refresh=datetime.now().isoformat()
        )

        graph = _build_dependency_graph(services)

        catalog = {
            "services": [s.model_dump() for s in services],
            "stats": stats.model_dump(),
            "graph": graph.model_dump(),
            "timestamp": datetime.now().isoformat()
        }

        # Write to cache file
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(catalog, indent=2))

        _cache = catalog
        _last_refresh = datetime.now()

        log.info("Catalog refreshed: %d services discovered", len(services))
        return catalog

    except Exception as e:
        log.error("Failed to refresh catalog: %s", e)
        raise


# Background refresh task
async def _background_refresh():
    """Background task to refresh catalog periodically."""
    while True:
        try:
            await _refresh_catalog()
        except Exception as e:
            log.error("Background refresh failed: %s", e)
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Start background refresh task."""
    asyncio.create_task(_background_refresh())


# ======================================================================
# Endpoints
# ======================================================================

@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    return {
        "status": "ok",
        "module": "metacatalog",
        "version": "1.0.0",
        "cache_ready": bool(_cache)
    }


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get module status with catalog stats."""
    if not _cache:
        await _refresh_catalog()

    stats = _cache.get("stats", {})
    return {
        "module": "metacatalog",
        "status": "running",
        "total_services": stats.get("total_services", 0),
        "running": stats.get("running", 0),
        "stopped": stats.get("stopped", 0),
        "failed": stats.get("failed", 0),
        "last_refresh": stats.get("last_refresh")
    }


@router.get("/services")
async def get_services(
    category: Optional[str] = None,
    status: Optional[str] = None,
    installed_only: bool = False,
    user=Depends(require_jwt)
):
    """Get all services with optional filtering."""
    if not _cache:
        await _refresh_catalog()

    services = _cache.get("services", [])

    # Apply filters
    if category:
        services = [s for s in services if s.get("category") == category]
    if status:
        services = [s for s in services if s.get("status") == status]
    if installed_only:
        services = [s for s in services if s.get("installed")]

    return {
        "services": services,
        "count": len(services),
        "filters": {
            "category": category,
            "status": status,
            "installed_only": installed_only
        }
    }


@router.get("/service/{name}")
async def get_service(name: str, user=Depends(require_jwt)):
    """Get detailed information about a specific service."""
    # Normalize service name
    if not name.startswith("secubox-"):
        name = f"secubox-{name}"

    if not _cache:
        await _refresh_catalog()

    services = _cache.get("services", [])
    service = next((s for s in services if s.get("name") == name), None)

    if not service:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")

    # Get live status (may differ from cached)
    live_status = _get_service_status(name)
    service["status"] = live_status["status"]
    service["active_since"] = live_status["active_since"]
    service["memory_usage"] = live_status["memory_usage"]

    return service


@router.get("/dependencies")
async def get_dependencies(user=Depends(require_jwt)):
    """Get the full dependency graph."""
    if not _cache:
        await _refresh_catalog()

    return _cache.get("graph", {"nodes": [], "edges": []})


@router.get("/dependencies/{name}")
async def get_service_dependencies(name: str, user=Depends(require_jwt)):
    """Get dependencies for a specific service."""
    # Normalize service name
    if not name.startswith("secubox-"):
        name = f"secubox-{name}"

    if not _cache:
        await _refresh_catalog()

    services = _cache.get("services", [])
    service = next((s for s in services if s.get("name") == name), None)

    if not service:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")

    # Get full dependency tree (recursive)
    def get_deps(svc_name: str, visited: set) -> List[str]:
        if svc_name in visited:
            return []
        visited.add(svc_name)
        svc = next((s for s in services if s.get("name") == svc_name), None)
        if not svc:
            return []
        deps = list(svc.get("dependencies", []))
        for dep in svc.get("dependencies", []):
            deps.extend(get_deps(dep, visited))
        return deps

    all_deps = list(set(get_deps(name, set())))

    return {
        "service": name,
        "direct_dependencies": service.get("dependencies", []),
        "all_dependencies": all_deps,
        "dependents": service.get("dependents", [])
    }


@router.get("/endpoints")
async def get_all_endpoints(user=Depends(require_jwt)):
    """Get API endpoints for all services."""
    if not _cache:
        await _refresh_catalog()

    endpoints = []
    services = _cache.get("services", [])

    for svc in services:
        if svc.get("installed") and svc.get("status") == "running":
            name = svc.get("name", "").replace("secubox-", "")
            # Standard SecuBox API endpoints
            endpoints.append({
                "service": svc.get("name"),
                "base_path": f"/api/v1/{name}",
                "endpoints": [
                    {"method": "GET", "path": "/health", "description": "Health check", "auth": False},
                    {"method": "GET", "path": "/status", "description": "Service status", "auth": True},
                ]
            })

    return {
        "services": endpoints,
        "count": len(endpoints)
    }


@router.get("/endpoints/{name}")
async def get_service_endpoints(name: str, user=Depends(require_jwt)):
    """Get API endpoints for a specific service."""
    # Normalize service name
    if not name.startswith("secubox-"):
        name = f"secubox-{name}"

    if not _cache:
        await _refresh_catalog()

    services = _cache.get("services", [])
    service = next((s for s in services if s.get("name") == name), None)

    if not service:
        raise HTTPException(status_code=404, detail=f"Service '{name}' not found")

    short_name = name.replace("secubox-", "")
    base_path = f"/api/v1/{short_name}"

    # Try to fetch OpenAPI spec from the service
    openapi_endpoints = []
    socket_path = service.get("socket")

    if socket_path and Path(socket_path).exists() and service.get("status") == "running":
        try:
            # Try to get OpenAPI spec via Unix socket
            import urllib.request
            import socket as sock

            class UnixHTTPConnection:
                def __init__(self, socket_path):
                    self.socket_path = socket_path

                def request(self, method, path):
                    s = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect(self.socket_path)
                    request = f"{method} {path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
                    s.sendall(request.encode())
                    response = b""
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    s.close()
                    return response.decode()

            conn = UnixHTTPConnection(socket_path)
            response = conn.request("GET", "/openapi.json")

            # Parse response body (skip headers)
            if "\r\n\r\n" in response:
                body = response.split("\r\n\r\n", 1)[1]
                openapi = json.loads(body)

                for path, methods in openapi.get("paths", {}).items():
                    for method, details in methods.items():
                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            openapi_endpoints.append({
                                "method": method.upper(),
                                "path": path,
                                "description": details.get("summary", details.get("description", "")),
                                "auth": "security" in details or "security" in openapi
                            })
        except Exception as e:
            log.debug("Could not fetch OpenAPI for %s: %s", name, e)

    # Fallback to standard endpoints if OpenAPI not available
    if not openapi_endpoints:
        openapi_endpoints = [
            {"method": "GET", "path": "/health", "description": "Health check endpoint", "auth": False},
            {"method": "GET", "path": "/status", "description": "Service status and statistics", "auth": True},
        ]

    return {
        "service": name,
        "base_path": base_path,
        "socket": socket_path,
        "endpoints": openapi_endpoints
    }


@router.post("/refresh")
async def refresh_catalog(user=Depends(require_jwt)):
    """Force refresh the service catalog."""
    log.info("Manual catalog refresh requested")
    catalog = await _refresh_catalog()
    return {
        "success": True,
        "message": "Catalog refreshed",
        "stats": catalog.get("stats")
    }


@router.get("/categories")
async def get_categories(user=Depends(require_jwt)):
    """Get list of service categories with counts."""
    if not _cache:
        await _refresh_catalog()

    services = _cache.get("services", [])
    categories = {}

    for svc in services:
        cat = svc.get("category", "system")
        if cat not in categories:
            categories[cat] = {"name": cat, "total": 0, "running": 0, "installed": 0}
        categories[cat]["total"] += 1
        if svc.get("installed"):
            categories[cat]["installed"] += 1
        if svc.get("status") == "running":
            categories[cat]["running"] += 1

    return {
        "categories": list(categories.values())
    }


# Include router
app.include_router(router)
