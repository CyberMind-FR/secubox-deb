"""secubox-saas-relay -- SaaS/API Proxy Relay Module

SecuBox-Deb :: SaaS Relay
CyberMind -- https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Provides secure proxy relay for external SaaS APIs with:
- Encrypted API key storage
- Rate limiting and quota tracking
- Request/response logging
- Health checks for proxied services
"""
import os
import asyncio
import json
import hashlib
import time
import base64
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
from cryptography.fernet import Fernet

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

try:
    import httpx
except ImportError:
    httpx = None

app = FastAPI(title="secubox-saas-relay", version="1.0.0", root_path="/api/v1/saas-relay")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("saas-relay")

# ============================================================================
# Configuration Paths
# ============================================================================
DATA_DIR = Path("/var/lib/secubox/saas-relay")
SERVICES_FILE = DATA_DIR / "services.json"
KEYS_FILE = DATA_DIR / "keys.enc"
STATS_FILE = DATA_DIR / "stats.json"
LOGS_FILE = DATA_DIR / "request_logs.json"
KEY_FILE = Path("/etc/secubox/secrets/saas-relay.key")
CACHE_DIR = Path("/var/cache/secubox/saas-relay")

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# Models
# ============================================================================
class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ServiceType(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    WEBHOOK = "webhook"


class SaaSService(BaseModel):
    name: str = Field(..., description="Unique service identifier")
    display_name: str = Field(..., description="Human-readable name")
    base_url: str = Field(..., description="Base URL for the SaaS API")
    service_type: ServiceType = ServiceType.REST
    auth_header: str = Field(default="Authorization", description="Header name for API key")
    auth_prefix: str = Field(default="Bearer ", description="Prefix for auth token")
    health_endpoint: Optional[str] = Field(default=None, description="Health check endpoint")
    rate_limit: int = Field(default=100, description="Requests per minute")
    quota_daily: int = Field(default=10000, description="Daily request quota")
    enabled: bool = True
    timeout: int = Field(default=30, description="Request timeout in seconds")
    description: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ServiceStats(BaseModel):
    service_name: str
    requests_today: int = 0
    requests_total: int = 0
    last_request: Optional[str] = None
    last_success: Optional[str] = None
    last_error: Optional[str] = None
    avg_response_time_ms: float = 0.0
    error_rate: float = 0.0
    health_status: HealthStatus = HealthStatus.UNKNOWN


class RequestLog(BaseModel):
    timestamp: str
    service: str
    method: str
    path: str
    status_code: int
    response_time_ms: float
    error: Optional[str] = None


class AddServiceRequest(BaseModel):
    name: str
    display_name: str
    base_url: str
    service_type: ServiceType = ServiceType.REST
    api_key: str = Field(..., description="API key to store (will be encrypted)")
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    health_endpoint: Optional[str] = None
    rate_limit: int = 100
    quota_daily: int = 10000
    timeout: int = 30
    description: Optional[str] = None


class UpdateServiceRequest(BaseModel):
    display_name: Optional[str] = None
    base_url: Optional[str] = None
    service_type: Optional[ServiceType] = None
    auth_header: Optional[str] = None
    auth_prefix: Optional[str] = None
    health_endpoint: Optional[str] = None
    rate_limit: Optional[int] = None
    quota_daily: Optional[int] = None
    timeout: Optional[int] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


class UpdateKeyRequest(BaseModel):
    api_key: str


# ============================================================================
# Encryption Utilities
# ============================================================================
def _get_encryption_key() -> bytes:
    """Get or create encryption key for API keys."""
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    # Generate new key
    key = Fernet.generate_key()
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


def _encrypt_key(api_key: str) -> str:
    """Encrypt an API key."""
    f = Fernet(_get_encryption_key())
    return f.encrypt(api_key.encode()).decode()


def _decrypt_key(encrypted_key: str) -> str:
    """Decrypt an API key."""
    f = Fernet(_get_encryption_key())
    return f.decrypt(encrypted_key.encode()).decode()


# ============================================================================
# Data Storage Utilities
# ============================================================================
def _load_json(path: Path, default=None) -> Any:
    """Load JSON from file with default fallback."""
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError) as e:
        log.warning("Failed to load %s: %s", path, e)
    return default


def _save_json(path: Path, data: Any):
    """Save JSON to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _load_services() -> Dict[str, dict]:
    """Load services configuration."""
    return _load_json(SERVICES_FILE, {"services": {}}).get("services", {})


def _save_services(services: Dict[str, dict]):
    """Save services configuration."""
    _save_json(SERVICES_FILE, {"services": services})


def _load_keys() -> Dict[str, str]:
    """Load encrypted API keys."""
    return _load_json(KEYS_FILE, {"keys": {}}).get("keys", {})


def _save_keys(keys: Dict[str, str]):
    """Save encrypted API keys."""
    _save_json(KEYS_FILE, {"keys": keys})
    KEYS_FILE.chmod(0o600)


def _load_stats() -> Dict[str, dict]:
    """Load service statistics."""
    return _load_json(STATS_FILE, {"stats": {}}).get("stats", {})


def _save_stats(stats: Dict[str, dict]):
    """Save service statistics."""
    _save_json(STATS_FILE, {"stats": stats})


def _load_logs() -> List[dict]:
    """Load request logs."""
    return _load_json(LOGS_FILE, {"logs": []}).get("logs", [])


def _save_logs(logs: List[dict]):
    """Save request logs, keeping last 1000 entries."""
    _save_json(LOGS_FILE, {"logs": logs[-1000:]})


# ============================================================================
# Rate Limiting
# ============================================================================
class RateLimiter:
    """Simple rate limiter per service."""
    def __init__(self):
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def check(self, service_name: str, limit: int) -> bool:
        """Check if request is within rate limit. Returns True if allowed."""
        now = time.time()
        window = 60  # 1 minute window

        with self._lock:
            if service_name not in self._requests:
                self._requests[service_name] = []

            # Remove old timestamps
            self._requests[service_name] = [
                ts for ts in self._requests[service_name]
                if now - ts < window
            ]

            if len(self._requests[service_name]) >= limit:
                return False

            self._requests[service_name].append(now)
            return True


rate_limiter = RateLimiter()


# ============================================================================
# Health Check Background Task
# ============================================================================
_health_check_task: Optional[asyncio.Task] = None
_health_cache: Dict[str, dict] = {}


async def _check_service_health(service: dict) -> dict:
    """Check health of a single service."""
    if not httpx:
        return {"status": HealthStatus.UNKNOWN, "message": "httpx not installed"}

    health_endpoint = service.get("health_endpoint")
    if not health_endpoint:
        return {"status": HealthStatus.UNKNOWN, "message": "No health endpoint configured"}

    keys = _load_keys()
    api_key = keys.get(service["name"])

    try:
        url = service["base_url"].rstrip("/") + health_endpoint
        headers = {}
        if api_key:
            decrypted_key = _decrypt_key(api_key)
            headers[service.get("auth_header", "Authorization")] = (
                service.get("auth_prefix", "Bearer ") + decrypted_key
            )

        async with httpx.AsyncClient(timeout=10) as client:
            start = time.time()
            resp = await client.get(url, headers=headers)
            elapsed = (time.time() - start) * 1000

            if resp.status_code < 400:
                return {
                    "status": HealthStatus.HEALTHY,
                    "response_time_ms": elapsed,
                    "status_code": resp.status_code,
                    "checked_at": datetime.now().isoformat()
                }
            else:
                return {
                    "status": HealthStatus.DEGRADED,
                    "response_time_ms": elapsed,
                    "status_code": resp.status_code,
                    "message": f"HTTP {resp.status_code}",
                    "checked_at": datetime.now().isoformat()
                }
    except Exception as e:
        return {
            "status": HealthStatus.UNHEALTHY,
            "message": str(e),
            "checked_at": datetime.now().isoformat()
        }


async def _periodic_health_check():
    """Background task to check health of all services."""
    global _health_cache

    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            services = _load_services()
            for name, service in services.items():
                if service.get("enabled", True):
                    health = await _check_service_health(service)
                    _health_cache[name] = health
                    log.debug("Health check %s: %s", name, health.get("status"))

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("Health check error: %s", e)


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _health_check_task
    _health_check_task = asyncio.create_task(_periodic_health_check())
    log.info("secubox-saas-relay started")


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _health_check_task
    if _health_check_task:
        _health_check_task.cancel()


# ============================================================================
# Configuration Helper
# ============================================================================
def _cfg() -> dict:
    """Get module configuration."""
    cfg = get_config("saas-relay")
    return {
        "log_requests": cfg.get("log_requests", True) if cfg else True,
        "default_timeout": cfg.get("default_timeout", 30) if cfg else 30,
        "max_services": cfg.get("max_services", 50) if cfg else 50,
    }


# ============================================================================
# API Endpoints - Public
# ============================================================================
@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    services = _load_services()
    enabled_count = sum(1 for s in services.values() if s.get("enabled", True))
    healthy_count = sum(
        1 for name in services
        if _health_cache.get(name, {}).get("status") == HealthStatus.HEALTHY
    )

    status = "healthy"
    if enabled_count > 0 and healthy_count < enabled_count:
        status = "degraded" if healthy_count > 0 else "unhealthy"

    return {
        "status": status,
        "module": "saas-relay",
        "services": {
            "total": len(services),
            "enabled": enabled_count,
            "healthy": healthy_count
        }
    }


@router.get("/status")
async def status():
    """Get module status (public)."""
    services = _load_services()
    stats = _load_stats()

    # Calculate totals
    total_requests = sum(s.get("requests_total", 0) for s in stats.values())
    requests_today = sum(s.get("requests_today", 0) for s in stats.values())

    return {
        "services_count": len(services),
        "enabled_count": sum(1 for s in services.values() if s.get("enabled", True)),
        "total_requests": total_requests,
        "requests_today": requests_today,
        "healthy_services": sum(
            1 for name in services
            if _health_cache.get(name, {}).get("status") == HealthStatus.HEALTHY
        )
    }


# ============================================================================
# API Endpoints - Services Management (Authenticated)
# ============================================================================
@router.get("/services", dependencies=[Depends(require_jwt)])
async def list_services():
    """List all configured SaaS services."""
    services = _load_services()
    stats = _load_stats()

    result = []
    for name, service in services.items():
        service_stats = stats.get(name, {})
        health = _health_cache.get(name, {"status": HealthStatus.UNKNOWN})

        result.append({
            **service,
            "health_status": health.get("status", HealthStatus.UNKNOWN),
            "last_health_check": health.get("checked_at"),
            "requests_today": service_stats.get("requests_today", 0),
            "requests_total": service_stats.get("requests_total", 0),
            "last_request": service_stats.get("last_request"),
            "error_rate": service_stats.get("error_rate", 0.0)
        })

    return {"services": result}


@router.get("/service/{name}", dependencies=[Depends(require_jwt)])
async def get_service(name: str):
    """Get details for a specific service."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    service = services[name]
    stats = _load_stats().get(name, {})
    health = _health_cache.get(name, {"status": HealthStatus.UNKNOWN})
    keys = _load_keys()

    return {
        **service,
        "health_status": health.get("status", HealthStatus.UNKNOWN),
        "health_details": health,
        "has_api_key": name in keys,
        "stats": stats
    }


@router.post("/service/add", dependencies=[Depends(require_jwt)])
async def add_service(req: AddServiceRequest):
    """Add a new SaaS service configuration."""
    services = _load_services()
    cfg = _cfg()

    if len(services) >= cfg["max_services"]:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum services limit ({cfg['max_services']}) reached"
        )

    if req.name in services:
        raise HTTPException(status_code=400, detail="Service already exists")

    # Validate name (alphanumeric + hyphens only)
    if not req.name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Service name must be alphanumeric with hyphens/underscores only"
        )

    now = datetime.now().isoformat()

    # Create service config
    service = {
        "name": req.name,
        "display_name": req.display_name,
        "base_url": req.base_url,
        "service_type": req.service_type.value,
        "auth_header": req.auth_header,
        "auth_prefix": req.auth_prefix,
        "health_endpoint": req.health_endpoint,
        "rate_limit": req.rate_limit,
        "quota_daily": req.quota_daily,
        "timeout": req.timeout,
        "description": req.description,
        "enabled": True,
        "created_at": now,
        "updated_at": now
    }

    services[req.name] = service
    _save_services(services)

    # Store encrypted API key
    keys = _load_keys()
    keys[req.name] = _encrypt_key(req.api_key)
    _save_keys(keys)

    log.info("Added service: %s -> %s", req.name, req.base_url)

    return {"success": True, "service": service}


@router.put("/service/{name}", dependencies=[Depends(require_jwt)])
async def update_service(name: str, req: UpdateServiceRequest):
    """Update an existing service configuration."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    service = services[name]

    # Update fields if provided
    if req.display_name is not None:
        service["display_name"] = req.display_name
    if req.base_url is not None:
        service["base_url"] = req.base_url
    if req.service_type is not None:
        service["service_type"] = req.service_type.value
    if req.auth_header is not None:
        service["auth_header"] = req.auth_header
    if req.auth_prefix is not None:
        service["auth_prefix"] = req.auth_prefix
    if req.health_endpoint is not None:
        service["health_endpoint"] = req.health_endpoint
    if req.rate_limit is not None:
        service["rate_limit"] = req.rate_limit
    if req.quota_daily is not None:
        service["quota_daily"] = req.quota_daily
    if req.timeout is not None:
        service["timeout"] = req.timeout
    if req.description is not None:
        service["description"] = req.description
    if req.enabled is not None:
        service["enabled"] = req.enabled

    service["updated_at"] = datetime.now().isoformat()
    services[name] = service
    _save_services(services)

    log.info("Updated service: %s", name)

    return {"success": True, "service": service}


@router.post("/service/{name}/toggle", dependencies=[Depends(require_jwt)])
async def toggle_service(name: str):
    """Toggle service enabled/disabled state."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    services[name]["enabled"] = not services[name].get("enabled", True)
    services[name]["updated_at"] = datetime.now().isoformat()
    _save_services(services)

    log.info("Toggled service %s: enabled=%s", name, services[name]["enabled"])

    return {"success": True, "enabled": services[name]["enabled"]}


@router.delete("/service/{name}", dependencies=[Depends(require_jwt)])
async def remove_service(name: str):
    """Remove a SaaS service configuration."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    del services[name]
    _save_services(services)

    # Remove API key
    keys = _load_keys()
    if name in keys:
        del keys[name]
        _save_keys(keys)

    # Remove stats
    stats = _load_stats()
    if name in stats:
        del stats[name]
        _save_stats(stats)

    # Remove from health cache
    if name in _health_cache:
        del _health_cache[name]

    log.info("Removed service: %s", name)

    return {"success": True, "removed": name}


# ============================================================================
# API Endpoints - API Key Management (Authenticated)
# ============================================================================
@router.get("/keys", dependencies=[Depends(require_jwt)])
async def list_keys():
    """List services with API keys (masked)."""
    keys = _load_keys()
    services = _load_services()

    result = []
    for name in services:
        has_key = name in keys
        result.append({
            "service": name,
            "display_name": services[name].get("display_name", name),
            "has_key": has_key,
            "key_preview": "****" + _decrypt_key(keys[name])[-4:] if has_key else None
        })

    return {"keys": result}


@router.put("/keys/{name}", dependencies=[Depends(require_jwt)])
async def update_key(name: str, req: UpdateKeyRequest):
    """Update API key for a service."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    keys = _load_keys()
    keys[name] = _encrypt_key(req.api_key)
    _save_keys(keys)

    log.info("Updated API key for service: %s", name)

    return {"success": True, "service": name}


@router.delete("/keys/{name}", dependencies=[Depends(require_jwt)])
async def delete_key(name: str):
    """Delete API key for a service."""
    keys = _load_keys()
    if name not in keys:
        raise HTTPException(status_code=404, detail="API key not found")

    del keys[name]
    _save_keys(keys)

    log.info("Deleted API key for service: %s", name)

    return {"success": True, "service": name}


# ============================================================================
# API Endpoints - Statistics (Authenticated)
# ============================================================================
@router.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get usage statistics for all services."""
    services = _load_services()
    stats = _load_stats()

    result = []
    for name, service in services.items():
        service_stats = stats.get(name, {})
        result.append({
            "service": name,
            "display_name": service.get("display_name", name),
            "requests_today": service_stats.get("requests_today", 0),
            "requests_total": service_stats.get("requests_total", 0),
            "quota_daily": service.get("quota_daily", 10000),
            "quota_used_percent": round(
                service_stats.get("requests_today", 0) / service.get("quota_daily", 10000) * 100, 1
            ),
            "avg_response_time_ms": service_stats.get("avg_response_time_ms", 0),
            "error_rate": service_stats.get("error_rate", 0),
            "last_request": service_stats.get("last_request"),
            "last_error": service_stats.get("last_error")
        })

    return {"stats": result}


@router.get("/stats/{name}", dependencies=[Depends(require_jwt)])
async def get_service_stats(name: str):
    """Get detailed statistics for a specific service."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    stats = _load_stats().get(name, {})
    service = services[name]

    return {
        "service": name,
        "display_name": service.get("display_name", name),
        "quota_daily": service.get("quota_daily", 10000),
        "rate_limit": service.get("rate_limit", 100),
        **stats
    }


@router.post("/stats/reset/{name}", dependencies=[Depends(require_jwt)])
async def reset_service_stats(name: str):
    """Reset statistics for a specific service."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    stats = _load_stats()
    if name in stats:
        stats[name] = {
            "requests_today": 0,
            "requests_total": 0,
            "avg_response_time_ms": 0,
            "error_rate": 0,
            "reset_at": datetime.now().isoformat()
        }
        _save_stats(stats)

    log.info("Reset stats for service: %s", name)

    return {"success": True, "service": name}


# ============================================================================
# API Endpoints - Logs (Authenticated)
# ============================================================================
@router.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(
    service: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0)
):
    """Get request logs."""
    logs = _load_logs()

    # Filter by service if specified
    if service:
        logs = [log for log in logs if log.get("service") == service]

    # Sort by timestamp descending
    logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "logs": logs[offset:offset + limit],
        "total": len(logs),
        "offset": offset,
        "limit": limit
    }


@router.delete("/logs", dependencies=[Depends(require_jwt)])
async def clear_logs(service: Optional[str] = None):
    """Clear request logs."""
    if service:
        logs = _load_logs()
        logs = [log for log in logs if log.get("service") != service]
        _save_logs(logs)
        log.info("Cleared logs for service: %s", service)
    else:
        _save_logs([])
        log.info("Cleared all logs")

    return {"success": True}


# ============================================================================
# API Endpoints - Health Checks (Authenticated)
# ============================================================================
@router.post("/service/{name}/check", dependencies=[Depends(require_jwt)])
async def check_service_health(name: str):
    """Trigger immediate health check for a service."""
    services = _load_services()
    if name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    health = await _check_service_health(services[name])
    _health_cache[name] = health

    return {"service": name, "health": health}


@router.get("/health/all", dependencies=[Depends(require_jwt)])
async def get_all_health():
    """Get health status for all services."""
    services = _load_services()

    result = []
    for name, service in services.items():
        health = _health_cache.get(name, {"status": HealthStatus.UNKNOWN})
        result.append({
            "service": name,
            "display_name": service.get("display_name", name),
            "enabled": service.get("enabled", True),
            "health": health
        })

    return {"health": result}


# ============================================================================
# API Endpoints - Proxy (Authenticated)
# ============================================================================
@router.api_route("/proxy/{service_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(
    service_name: str,
    path: str,
    user=Depends(require_jwt)
):
    """Proxy requests to SaaS services."""
    if not httpx:
        raise HTTPException(status_code=500, detail="httpx not installed")

    services = _load_services()
    if service_name not in services:
        raise HTTPException(status_code=404, detail="Service not found")

    service = services[service_name]
    if not service.get("enabled", True):
        raise HTTPException(status_code=403, detail="Service is disabled")

    # Check rate limit
    if not rate_limiter.check(service_name, service.get("rate_limit", 100)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Check daily quota
    stats = _load_stats()
    service_stats = stats.get(service_name, {"requests_today": 0})
    if service_stats.get("requests_today", 0) >= service.get("quota_daily", 10000):
        raise HTTPException(status_code=429, detail="Daily quota exceeded")

    # Get API key
    keys = _load_keys()
    if service_name not in keys:
        raise HTTPException(status_code=400, detail="No API key configured for service")

    try:
        api_key = _decrypt_key(keys[service_name])
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decrypt API key")

    # Build request
    url = service["base_url"].rstrip("/") + "/" + path
    headers = {
        service.get("auth_header", "Authorization"):
            service.get("auth_prefix", "Bearer ") + api_key
    }

    # Make request
    start_time = time.time()
    error_msg = None
    status_code = 0

    try:
        async with httpx.AsyncClient(timeout=service.get("timeout", 30)) as client:
            # Forward request - simplified for now
            from starlette.requests import Request
            from fastapi import Request as FastAPIRequest

            resp = await client.get(url, headers=headers)
            status_code = resp.status_code
            response_time = (time.time() - start_time) * 1000

            # Update stats
            _update_stats(service_name, response_time, status_code >= 400)

            # Log request
            if _cfg()["log_requests"]:
                _log_request(service_name, "GET", path, status_code, response_time)

            return resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"response": resp.text}

    except httpx.TimeoutException:
        error_msg = "Request timeout"
        _update_stats(service_name, 0, True)
        _log_request(service_name, "GET", path, 0, 0, error_msg)
        raise HTTPException(status_code=504, detail=error_msg)
    except Exception as e:
        error_msg = str(e)
        _update_stats(service_name, 0, True)
        _log_request(service_name, "GET", path, 0, 0, error_msg)
        raise HTTPException(status_code=502, detail=error_msg)


def _update_stats(service_name: str, response_time_ms: float, is_error: bool):
    """Update service statistics."""
    stats = _load_stats()

    if service_name not in stats:
        stats[service_name] = {
            "requests_today": 0,
            "requests_total": 0,
            "avg_response_time_ms": 0,
            "error_count": 0,
            "error_rate": 0
        }

    s = stats[service_name]
    s["requests_today"] = s.get("requests_today", 0) + 1
    s["requests_total"] = s.get("requests_total", 0) + 1
    s["last_request"] = datetime.now().isoformat()

    if is_error:
        s["error_count"] = s.get("error_count", 0) + 1
        s["last_error"] = datetime.now().isoformat()

    # Update rolling average response time
    total = s.get("requests_total", 1)
    old_avg = s.get("avg_response_time_ms", 0)
    s["avg_response_time_ms"] = ((old_avg * (total - 1)) + response_time_ms) / total

    # Update error rate
    s["error_rate"] = round(s.get("error_count", 0) / total * 100, 2)

    if not is_error:
        s["last_success"] = datetime.now().isoformat()

    _save_stats(stats)


def _log_request(
    service: str,
    method: str,
    path: str,
    status_code: int,
    response_time_ms: float,
    error: Optional[str] = None
):
    """Log a proxy request."""
    logs = _load_logs()
    logs.append({
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "method": method,
        "path": path,
        "status_code": status_code,
        "response_time_ms": round(response_time_ms, 2),
        "error": error
    })
    _save_logs(logs)


# ============================================================================
# Three-Fold Architecture Endpoints
# ============================================================================
@router.get("/components")
async def components():
    """List system components (public)."""
    services = _load_services()
    keys = _load_keys()

    return {
        "components": [
            {
                "name": "SaaS Relay API",
                "type": "service",
                "description": "Proxy relay for external SaaS APIs",
                "running": True
            },
            {
                "name": "Encryption Module",
                "type": "security",
                "description": "API key encryption (Fernet)",
                "available": KEY_FILE.exists()
            },
            {
                "name": "Services Store",
                "type": "storage",
                "description": "Service configurations",
                "path": str(SERVICES_FILE),
                "count": len(services)
            },
            {
                "name": "Keys Store",
                "type": "storage",
                "description": "Encrypted API keys",
                "path": str(KEYS_FILE),
                "count": len(keys)
            },
            {
                "name": "Health Monitor",
                "type": "background",
                "description": "Periodic health checks",
                "running": _health_check_task is not None and not _health_check_task.done()
            }
        ]
    }


@router.get("/access")
async def access():
    """Get access information (public)."""
    services = _load_services()

    access_points = [
        {
            "name": "SaaS Relay Dashboard",
            "type": "dashboard",
            "path": "/saas-relay/",
            "description": "Web management interface"
        },
        {
            "name": "API Endpoint",
            "type": "api",
            "path": "/api/v1/saas-relay/",
            "description": "REST API endpoint"
        }
    ]

    # Add service endpoints
    for name, service in services.items():
        if service.get("enabled", True):
            access_points.append({
                "name": service.get("display_name", name),
                "type": "proxy",
                "path": f"/api/v1/saas-relay/proxy/{name}/",
                "target": service.get("base_url"),
                "health": _health_cache.get(name, {}).get("status", "unknown")
            })

    return {"access": access_points}


app.include_router(router)
