"""SecuBox DNS Provider API - Multi-Provider DNS Management

Features:
- Multi-provider DNS API (OVH, Gandi, Cloudflare, Route53)
- Domain management
- DNS record CRUD
- ACME DNS-01 challenge support
- Dynamic DNS updates
- Zone import/export
- API key management
- Audit logging

CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
"""
import asyncio
import json
import hashlib
import hmac
import re
import time
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod

from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox DNS Provider", version="1.0.0")
config = get_config("dns-provider")

# Data paths
DATA_DIR = Path("/var/lib/secubox/dns-provider")
CONFIG_FILE = DATA_DIR / "config.json"
PROVIDERS_FILE = DATA_DIR / "providers.json"
AUDIT_LOG_FILE = DATA_DIR / "audit.log"
CACHE_FILE = DATA_DIR / "cache.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Enums and Models
# ===========================================================================

class ProviderType(str, Enum):
    OVH = "ovh"
    GANDI = "gandi"
    CLOUDFLARE = "cloudflare"
    ROUTE53 = "route53"


class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"


class ProviderCredentials(BaseModel):
    provider: ProviderType
    name: str = Field(..., min_length=1)
    credentials: Dict[str, str]
    enabled: bool = True

    @field_validator('credentials')
    @classmethod
    def validate_credentials(cls, v, info):
        provider = info.data.get('provider')
        required = {
            'ovh': ['application_key', 'application_secret', 'consumer_key', 'endpoint'],
            'gandi': ['api_key'],
            'cloudflare': ['api_token'],
            'route53': ['access_key_id', 'secret_access_key', 'region']
        }
        if provider and provider in required:
            missing = [k for k in required[provider] if k not in v or not v[k]]
            if missing:
                raise ValueError(f"Missing credentials: {missing}")
        return v


class RecordCreate(BaseModel):
    type: RecordType
    name: str
    value: str
    ttl: int = Field(default=300, ge=60, le=86400)
    priority: Optional[int] = None  # For MX records


class RecordUpdate(BaseModel):
    type: Optional[RecordType] = None
    name: Optional[str] = None
    value: Optional[str] = None
    ttl: Optional[int] = Field(default=None, ge=60, le=86400)
    priority: Optional[int] = None


class ACMEChallenge(BaseModel):
    domain: str
    token: str
    key_authorization: str


class DDNSUpdate(BaseModel):
    domain: str
    subdomain: str = "@"
    ip: Optional[str] = None  # Auto-detect if not provided
    ipv6: Optional[str] = None


class ZoneImport(BaseModel):
    domain: str
    zone_data: str  # BIND zone file format
    provider_id: str


# ===========================================================================
# Helpers
# ===========================================================================

def _load_json(path: Path, default=None) -> Any:
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _audit_log(action: str, details: Dict[str, Any], user: str = "system"):
    """Append to audit log (CSPN requirement: immutable audit trail)."""
    try:
        with open(AUDIT_LOG_FILE, "a") as f:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "user": user,
                "details": details
            }
            f.write(json.dumps(entry) + "\n")
    except IOError:
        pass


def _mask_credentials(creds: Dict[str, str]) -> Dict[str, str]:
    """Mask sensitive credential values."""
    return {k: v[:4] + "****" if len(v) > 8 else "****" for k, v in creds.items()}


def _generate_id() -> str:
    """Generate unique provider ID."""
    return hashlib.sha256(f"{time.time()}{id(object())}".encode()).hexdigest()[:12]


# ===========================================================================
# Stats Cache
# ===========================================================================

class StatsCache:
    """Thread-safe cache with TTL."""
    def __init__(self, ttl_seconds: int = 60):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def clear(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=300)


# ===========================================================================
# DNS Provider Adapters (Abstract Pattern)
# ===========================================================================

class DNSProviderAdapter(ABC):
    """Abstract base for DNS provider adapters."""

    def __init__(self, credentials: Dict[str, str]):
        self.credentials = credentials

    @abstractmethod
    async def list_domains(self) -> List[Dict[str, Any]]:
        """List all domains."""
        pass

    @abstractmethod
    async def list_records(self, domain: str) -> List[Dict[str, Any]]:
        """List records for domain."""
        pass

    @abstractmethod
    async def create_record(self, domain: str, record: RecordCreate) -> Dict[str, Any]:
        """Create DNS record."""
        pass

    @abstractmethod
    async def update_record(self, domain: str, record_id: str, record: RecordUpdate) -> Dict[str, Any]:
        """Update DNS record."""
        pass

    @abstractmethod
    async def delete_record(self, domain: str, record_id: str) -> bool:
        """Delete DNS record."""
        pass

    @abstractmethod
    async def create_acme_challenge(self, domain: str, token: str, key_auth: str) -> bool:
        """Create ACME DNS-01 challenge TXT record."""
        pass

    @abstractmethod
    async def delete_acme_challenge(self, domain: str, token: str) -> bool:
        """Delete ACME DNS-01 challenge TXT record."""
        pass

    @abstractmethod
    async def export_zone(self, domain: str) -> str:
        """Export zone as BIND format."""
        pass


class CloudflareAdapter(DNSProviderAdapter):
    """Cloudflare DNS API adapter."""

    API_URL = "https://api.cloudflare.com/client/v4"

    async def _request(self, method: str, path: str, data: Dict = None) -> Dict:
        import httpx
        headers = {
            "Authorization": f"Bearer {self.credentials.get('api_token')}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(timeout=30) as client:
            if method == "GET":
                resp = await client.get(f"{self.API_URL}{path}", headers=headers)
            elif method == "POST":
                resp = await client.post(f"{self.API_URL}{path}", headers=headers, json=data)
            elif method == "PUT":
                resp = await client.put(f"{self.API_URL}{path}", headers=headers, json=data)
            elif method == "DELETE":
                resp = await client.delete(f"{self.API_URL}{path}", headers=headers)
            else:
                raise ValueError(f"Unknown method: {method}")
            return resp.json()

    async def _get_zone_id(self, domain: str) -> Optional[str]:
        result = await self._request("GET", f"/zones?name={domain}")
        if result.get("success") and result.get("result"):
            return result["result"][0]["id"]
        return None

    async def list_domains(self) -> List[Dict[str, Any]]:
        result = await self._request("GET", "/zones")
        if result.get("success"):
            return [{"name": z["name"], "id": z["id"], "status": z["status"]}
                    for z in result.get("result", [])]
        return []

    async def list_records(self, domain: str) -> List[Dict[str, Any]]:
        zone_id = await self._get_zone_id(domain)
        if not zone_id:
            return []
        result = await self._request("GET", f"/zones/{zone_id}/dns_records")
        if result.get("success"):
            return [{
                "id": r["id"],
                "type": r["type"],
                "name": r["name"],
                "value": r["content"],
                "ttl": r["ttl"],
                "priority": r.get("priority")
            } for r in result.get("result", [])]
        return []

    async def create_record(self, domain: str, record: RecordCreate) -> Dict[str, Any]:
        zone_id = await self._get_zone_id(domain)
        if not zone_id:
            raise HTTPException(404, f"Zone {domain} not found")
        data = {
            "type": record.type.value,
            "name": record.name,
            "content": record.value,
            "ttl": record.ttl
        }
        if record.priority:
            data["priority"] = record.priority
        result = await self._request("POST", f"/zones/{zone_id}/dns_records", data)
        if result.get("success"):
            return {"id": result["result"]["id"], "success": True}
        raise HTTPException(400, result.get("errors", [{}])[0].get("message", "Failed"))

    async def update_record(self, domain: str, record_id: str, record: RecordUpdate) -> Dict[str, Any]:
        zone_id = await self._get_zone_id(domain)
        if not zone_id:
            raise HTTPException(404, f"Zone {domain} not found")

        # Get existing record
        existing = await self._request("GET", f"/zones/{zone_id}/dns_records/{record_id}")
        if not existing.get("success"):
            raise HTTPException(404, "Record not found")

        current = existing["result"]
        data = {
            "type": record.type.value if record.type else current["type"],
            "name": record.name if record.name else current["name"],
            "content": record.value if record.value else current["content"],
            "ttl": record.ttl if record.ttl else current["ttl"]
        }
        if record.priority:
            data["priority"] = record.priority

        result = await self._request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", data)
        if result.get("success"):
            return {"success": True}
        raise HTTPException(400, result.get("errors", [{}])[0].get("message", "Failed"))

    async def delete_record(self, domain: str, record_id: str) -> bool:
        zone_id = await self._get_zone_id(domain)
        if not zone_id:
            raise HTTPException(404, f"Zone {domain} not found")
        result = await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
        return result.get("success", False)

    async def create_acme_challenge(self, domain: str, token: str, key_auth: str) -> bool:
        record = RecordCreate(
            type=RecordType.TXT,
            name=f"_acme-challenge.{domain}",
            value=key_auth,
            ttl=60
        )
        try:
            await self.create_record(domain, record)
            return True
        except Exception:
            return False

    async def delete_acme_challenge(self, domain: str, token: str) -> bool:
        records = await self.list_records(domain)
        for r in records:
            if r["type"] == "TXT" and "_acme-challenge" in r["name"]:
                await self.delete_record(domain, r["id"])
                return True
        return False

    async def export_zone(self, domain: str) -> str:
        records = await self.list_records(domain)
        lines = [
            f"; Zone file for {domain}",
            f"; Exported from Cloudflare at {datetime.now().isoformat()}",
            f"$ORIGIN {domain}.",
            "$TTL 300",
            ""
        ]
        for r in records:
            name = r["name"].replace(f".{domain}", "") if r["name"] != domain else "@"
            ttl = r.get("ttl", 300)
            rtype = r["type"]
            value = r["value"]
            if r.get("priority"):
                lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{r['priority']} {value}")
            else:
                lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{value}")
        return "\n".join(lines)


class GandiAdapter(DNSProviderAdapter):
    """Gandi LiveDNS API adapter."""

    API_URL = "https://api.gandi.net/v5/livedns"

    async def _request(self, method: str, path: str, data: Dict = None) -> Any:
        import httpx
        headers = {
            "Authorization": f"Bearer {self.credentials.get('api_key')}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(timeout=30) as client:
            url = f"{self.API_URL}{path}"
            if method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "POST":
                resp = await client.post(url, headers=headers, json=data)
            elif method == "PUT":
                resp = await client.put(url, headers=headers, json=data)
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                raise ValueError(f"Unknown method: {method}")

            if resp.status_code == 204:
                return {"success": True}
            return resp.json()

    async def list_domains(self) -> List[Dict[str, Any]]:
        result = await self._request("GET", "/domains")
        if isinstance(result, list):
            return [{"name": d["fqdn"], "id": d["fqdn"], "status": "active"} for d in result]
        return []

    async def list_records(self, domain: str) -> List[Dict[str, Any]]:
        result = await self._request("GET", f"/domains/{domain}/records")
        if isinstance(result, list):
            records = []
            for r in result:
                for value in r.get("rrset_values", []):
                    records.append({
                        "id": f"{r['rrset_name']}_{r['rrset_type']}",
                        "type": r["rrset_type"],
                        "name": r["rrset_name"],
                        "value": value,
                        "ttl": r.get("rrset_ttl", 300)
                    })
            return records
        return []

    async def create_record(self, domain: str, record: RecordCreate) -> Dict[str, Any]:
        data = {
            "rrset_type": record.type.value,
            "rrset_name": record.name,
            "rrset_values": [record.value],
            "rrset_ttl": record.ttl
        }
        result = await self._request("POST", f"/domains/{domain}/records", data)
        return {"success": True, "id": f"{record.name}_{record.type.value}"}

    async def update_record(self, domain: str, record_id: str, record: RecordUpdate) -> Dict[str, Any]:
        name, rtype = record_id.rsplit("_", 1)
        data = {}
        if record.value:
            data["rrset_values"] = [record.value]
        if record.ttl:
            data["rrset_ttl"] = record.ttl
        await self._request("PUT", f"/domains/{domain}/records/{name}/{rtype}", data)
        return {"success": True}

    async def delete_record(self, domain: str, record_id: str) -> bool:
        name, rtype = record_id.rsplit("_", 1)
        await self._request("DELETE", f"/domains/{domain}/records/{name}/{rtype}")
        return True

    async def create_acme_challenge(self, domain: str, token: str, key_auth: str) -> bool:
        record = RecordCreate(
            type=RecordType.TXT,
            name="_acme-challenge",
            value=key_auth,
            ttl=60
        )
        try:
            await self.create_record(domain, record)
            return True
        except Exception:
            return False

    async def delete_acme_challenge(self, domain: str, token: str) -> bool:
        try:
            await self._request("DELETE", f"/domains/{domain}/records/_acme-challenge/TXT")
            return True
        except Exception:
            return False

    async def export_zone(self, domain: str) -> str:
        records = await self.list_records(domain)
        lines = [
            f"; Zone file for {domain}",
            f"; Exported from Gandi at {datetime.now().isoformat()}",
            f"$ORIGIN {domain}.",
            "$TTL 300",
            ""
        ]
        for r in records:
            name = r["name"] if r["name"] != "@" else "@"
            lines.append(f"{name}\t{r.get('ttl', 300)}\tIN\t{r['type']}\t{r['value']}")
        return "\n".join(lines)


class OVHAdapter(DNSProviderAdapter):
    """OVH DNS API adapter (simplified - uses external ovh library)."""

    async def list_domains(self) -> List[Dict[str, Any]]:
        # OVH requires complex signature - placeholder
        return [{"name": "example.com", "id": "example.com", "status": "active", "note": "OVH API not fully implemented"}]

    async def list_records(self, domain: str) -> List[Dict[str, Any]]:
        return []

    async def create_record(self, domain: str, record: RecordCreate) -> Dict[str, Any]:
        raise HTTPException(501, "OVH adapter requires ovh library")

    async def update_record(self, domain: str, record_id: str, record: RecordUpdate) -> Dict[str, Any]:
        raise HTTPException(501, "OVH adapter requires ovh library")

    async def delete_record(self, domain: str, record_id: str) -> bool:
        raise HTTPException(501, "OVH adapter requires ovh library")

    async def create_acme_challenge(self, domain: str, token: str, key_auth: str) -> bool:
        return False

    async def delete_acme_challenge(self, domain: str, token: str) -> bool:
        return False

    async def export_zone(self, domain: str) -> str:
        return f"; OVH zone export not implemented for {domain}"


class Route53Adapter(DNSProviderAdapter):
    """AWS Route53 DNS API adapter (simplified - uses boto3)."""

    async def list_domains(self) -> List[Dict[str, Any]]:
        return [{"name": "example.com", "id": "example.com", "status": "active", "note": "Route53 API not fully implemented"}]

    async def list_records(self, domain: str) -> List[Dict[str, Any]]:
        return []

    async def create_record(self, domain: str, record: RecordCreate) -> Dict[str, Any]:
        raise HTTPException(501, "Route53 adapter requires boto3 library")

    async def update_record(self, domain: str, record_id: str, record: RecordUpdate) -> Dict[str, Any]:
        raise HTTPException(501, "Route53 adapter requires boto3 library")

    async def delete_record(self, domain: str, record_id: str) -> bool:
        raise HTTPException(501, "Route53 adapter requires boto3 library")

    async def create_acme_challenge(self, domain: str, token: str, key_auth: str) -> bool:
        return False

    async def delete_acme_challenge(self, domain: str, token: str) -> bool:
        return False

    async def export_zone(self, domain: str) -> str:
        return f"; Route53 zone export not implemented for {domain}"


def get_adapter(provider_type: ProviderType, credentials: Dict[str, str]) -> DNSProviderAdapter:
    """Factory for DNS provider adapters."""
    adapters = {
        ProviderType.CLOUDFLARE: CloudflareAdapter,
        ProviderType.GANDI: GandiAdapter,
        ProviderType.OVH: OVHAdapter,
        ProviderType.ROUTE53: Route53Adapter,
    }
    adapter_class = adapters.get(provider_type)
    if not adapter_class:
        raise HTTPException(400, f"Unknown provider: {provider_type}")
    return adapter_class(credentials)


def _get_provider(provider_id: str) -> tuple:
    """Get provider config and adapter."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    for p in providers.get("providers", []):
        if p["id"] == provider_id:
            adapter = get_adapter(ProviderType(p["provider"]), p["credentials"])
            return p, adapter
    raise HTTPException(404, f"Provider {provider_id} not found")


# ===========================================================================
# Background Tasks
# ===========================================================================

_refresh_task: Optional[asyncio.Task] = None


async def _periodic_refresh():
    """Periodically refresh domain cache."""
    while True:
        try:
            await asyncio.sleep(300)  # Every 5 minutes

            providers = _load_json(PROVIDERS_FILE, {"providers": []})
            cache_data = {"updated": datetime.now().isoformat(), "domains": {}}

            for p in providers.get("providers", []):
                if not p.get("enabled", True):
                    continue
                try:
                    adapter = get_adapter(ProviderType(p["provider"]), p["credentials"])
                    domains = await adapter.list_domains()
                    cache_data["domains"][p["id"]] = domains
                except Exception:
                    pass

            _save_json(CACHE_FILE, cache_data)

        except asyncio.CancelledError:
            break
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    global _refresh_task
    _refresh_task = asyncio.create_task(_periodic_refresh())


@app.on_event("shutdown")
async def shutdown_event():
    global _refresh_task
    if _refresh_task:
        _refresh_task.cancel()


# ===========================================================================
# Health & Status Endpoints
# ===========================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    active = sum(1 for p in providers.get("providers", []) if p.get("enabled", True))

    return {
        "status": "ok" if active > 0 else "degraded",
        "module": "dns-provider",
        "version": "1.0.0",
        "providers_active": active
    }


@app.get("/status")
async def status():
    """Get service status."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    all_providers = providers.get("providers", [])

    return {
        "running": True,
        "providers_total": len(all_providers),
        "providers_active": sum(1 for p in all_providers if p.get("enabled", True)),
        "timestamp": datetime.now().isoformat()
    }


# ===========================================================================
# Configuration Endpoints
# ===========================================================================

@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get current configuration."""
    cfg = _load_json(CONFIG_FILE, {
        "default_ttl": 300,
        "acme_ttl": 60,
        "ddns_check_interval": 300,
        "audit_retention_days": 90
    })
    return cfg


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(new_config: Dict[str, Any]):
    """Update configuration."""
    cfg = _load_json(CONFIG_FILE, {})
    cfg.update(new_config)
    _save_json(CONFIG_FILE, cfg)
    _audit_log("config_updated", {"changes": list(new_config.keys())})
    return {"success": True, "config": cfg}


# ===========================================================================
# Provider Management
# ===========================================================================

@app.get("/providers", dependencies=[Depends(require_jwt)])
async def list_providers():
    """List configured DNS providers."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    result = []
    for p in providers.get("providers", []):
        result.append({
            "id": p["id"],
            "name": p["name"],
            "provider": p["provider"],
            "enabled": p.get("enabled", True),
            "credentials": _mask_credentials(p.get("credentials", {})),
            "created_at": p.get("created_at")
        })
    return {"providers": result}


@app.post("/provider", dependencies=[Depends(require_jwt)])
async def add_provider(data: ProviderCredentials, background_tasks: BackgroundTasks):
    """Add DNS provider credentials."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})

    provider_id = _generate_id()
    provider_entry = {
        "id": provider_id,
        "name": data.name,
        "provider": data.provider.value,
        "credentials": data.credentials,
        "enabled": data.enabled,
        "created_at": datetime.now().isoformat()
    }

    providers["providers"].append(provider_entry)
    _save_json(PROVIDERS_FILE, providers)

    _audit_log("provider_added", {
        "id": provider_id,
        "name": data.name,
        "provider": data.provider.value
    })

    stats_cache.clear()

    return {
        "success": True,
        "id": provider_id,
        "provider": {
            "id": provider_id,
            "name": data.name,
            "provider": data.provider.value,
            "enabled": data.enabled
        }
    }


@app.delete("/provider/{provider_id}", dependencies=[Depends(require_jwt)])
async def remove_provider(provider_id: str):
    """Remove DNS provider."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    original_len = len(providers["providers"])
    providers["providers"] = [p for p in providers["providers"] if p["id"] != provider_id]

    if len(providers["providers"]) == original_len:
        raise HTTPException(404, "Provider not found")

    _save_json(PROVIDERS_FILE, providers)
    _audit_log("provider_removed", {"id": provider_id})
    stats_cache.clear()

    return {"success": True}


@app.put("/provider/{provider_id}", dependencies=[Depends(require_jwt)])
async def update_provider(provider_id: str, updates: Dict[str, Any]):
    """Update provider settings."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})

    for p in providers["providers"]:
        if p["id"] == provider_id:
            if "enabled" in updates:
                p["enabled"] = updates["enabled"]
            if "name" in updates:
                p["name"] = updates["name"]
            if "credentials" in updates:
                p["credentials"].update(updates["credentials"])
            _save_json(PROVIDERS_FILE, providers)
            _audit_log("provider_updated", {"id": provider_id, "changes": list(updates.keys())})
            return {"success": True}

    raise HTTPException(404, "Provider not found")


# ===========================================================================
# Domain Management
# ===========================================================================

@app.get("/domains", dependencies=[Depends(require_jwt)])
async def list_domains(provider_id: Optional[str] = None):
    """List domains from all or specific provider."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    all_domains = []

    for p in providers.get("providers", []):
        if provider_id and p["id"] != provider_id:
            continue
        if not p.get("enabled", True):
            continue

        try:
            adapter = get_adapter(ProviderType(p["provider"]), p["credentials"])
            domains = await adapter.list_domains()
            for d in domains:
                d["provider_id"] = p["id"]
                d["provider_name"] = p["name"]
                d["provider_type"] = p["provider"]
            all_domains.extend(domains)
        except Exception as e:
            all_domains.append({
                "provider_id": p["id"],
                "provider_name": p["name"],
                "provider_type": p["provider"],
                "error": str(e)
            })

    return {"domains": all_domains}


@app.get("/domain/{domain_name}/records", dependencies=[Depends(require_jwt)])
async def list_records(domain_name: str, provider_id: Optional[str] = None):
    """List DNS records for domain."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})

    # Find the right provider
    for p in providers.get("providers", []):
        if provider_id and p["id"] != provider_id:
            continue
        if not p.get("enabled", True):
            continue

        try:
            adapter = get_adapter(ProviderType(p["provider"]), p["credentials"])
            domains = await adapter.list_domains()

            if any(d.get("name") == domain_name for d in domains):
                records = await adapter.list_records(domain_name)
                return {
                    "domain": domain_name,
                    "provider_id": p["id"],
                    "records": records
                }
        except Exception:
            continue

    raise HTTPException(404, f"Domain {domain_name} not found in any provider")


@app.post("/domain/{domain_name}/record", dependencies=[Depends(require_jwt)])
async def create_record(domain_name: str, record: RecordCreate, provider_id: str = Query(...)):
    """Create DNS record."""
    provider, adapter = _get_provider(provider_id)

    result = await adapter.create_record(domain_name, record)
    _audit_log("record_created", {
        "domain": domain_name,
        "provider": provider_id,
        "type": record.type.value,
        "name": record.name
    })

    return {"success": True, **result}


@app.put("/domain/{domain_name}/record/{record_id}", dependencies=[Depends(require_jwt)])
async def update_record_endpoint(
    domain_name: str,
    record_id: str,
    record: RecordUpdate,
    provider_id: str = Query(...)
):
    """Update DNS record."""
    provider, adapter = _get_provider(provider_id)

    result = await adapter.update_record(domain_name, record_id, record)
    _audit_log("record_updated", {
        "domain": domain_name,
        "provider": provider_id,
        "record_id": record_id
    })

    return {"success": True, **result}


@app.delete("/domain/{domain_name}/record/{record_id}", dependencies=[Depends(require_jwt)])
async def delete_record_endpoint(domain_name: str, record_id: str, provider_id: str = Query(...)):
    """Delete DNS record."""
    provider, adapter = _get_provider(provider_id)

    success = await adapter.delete_record(domain_name, record_id)
    _audit_log("record_deleted", {
        "domain": domain_name,
        "provider": provider_id,
        "record_id": record_id
    })

    return {"success": success}


# ===========================================================================
# ACME DNS-01 Challenge
# ===========================================================================

@app.post("/acme/challenge", dependencies=[Depends(require_jwt)])
async def create_acme_challenge(challenge: ACMEChallenge, provider_id: str = Query(...)):
    """Create ACME DNS-01 challenge TXT record."""
    provider, adapter = _get_provider(provider_id)

    success = await adapter.create_acme_challenge(
        challenge.domain,
        challenge.token,
        challenge.key_authorization
    )

    _audit_log("acme_challenge_created", {
        "domain": challenge.domain,
        "provider": provider_id
    })

    return {
        "success": success,
        "domain": challenge.domain,
        "record": f"_acme-challenge.{challenge.domain}"
    }


@app.delete("/acme/challenge", dependencies=[Depends(require_jwt)])
async def delete_acme_challenge(domain: str, token: str, provider_id: str = Query(...)):
    """Delete ACME DNS-01 challenge TXT record."""
    provider, adapter = _get_provider(provider_id)

    success = await adapter.delete_acme_challenge(domain, token)
    _audit_log("acme_challenge_deleted", {"domain": domain, "provider": provider_id})

    return {"success": success}


# ===========================================================================
# Dynamic DNS
# ===========================================================================

@app.post("/ddns/update", dependencies=[Depends(require_jwt)])
async def ddns_update(update: DDNSUpdate, provider_id: str = Query(...)):
    """Update Dynamic DNS record."""
    provider, adapter = _get_provider(provider_id)

    # Auto-detect IP if not provided
    ip = update.ip
    if not ip:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.get("https://api.ipify.org?format=json")
                ip = resp.json().get("ip")
            except Exception:
                raise HTTPException(500, "Cannot detect public IP")

    # Find existing A record
    records = await adapter.list_records(update.domain)
    existing = None
    for r in records:
        if r["type"] == "A" and r["name"] == update.subdomain:
            existing = r
            break

    if existing:
        # Update existing
        record_update = RecordUpdate(value=ip)
        await adapter.update_record(update.domain, existing["id"], record_update)
        action = "updated"
    else:
        # Create new
        record = RecordCreate(type=RecordType.A, name=update.subdomain, value=ip, ttl=300)
        await adapter.create_record(update.domain, record)
        action = "created"

    _audit_log("ddns_update", {
        "domain": update.domain,
        "subdomain": update.subdomain,
        "ip": ip,
        "action": action
    })

    # Also handle IPv6 if provided
    if update.ipv6:
        existing_aaaa = None
        for r in records:
            if r["type"] == "AAAA" and r["name"] == update.subdomain:
                existing_aaaa = r
                break

        if existing_aaaa:
            record_update = RecordUpdate(value=update.ipv6)
            await adapter.update_record(update.domain, existing_aaaa["id"], record_update)
        else:
            record = RecordCreate(type=RecordType.AAAA, name=update.subdomain, value=update.ipv6, ttl=300)
            await adapter.create_record(update.domain, record)

    return {
        "success": True,
        "domain": update.domain,
        "subdomain": update.subdomain,
        "ipv4": ip,
        "ipv6": update.ipv6,
        "action": action
    }


# ===========================================================================
# Zone Import/Export
# ===========================================================================

@app.get("/zones/export/{domain}", dependencies=[Depends(require_jwt)])
async def export_zone(domain: str, provider_id: str = Query(...), format: str = Query(default="bind")):
    """Export DNS zone."""
    provider, adapter = _get_provider(provider_id)

    zone_data = await adapter.export_zone(domain)
    _audit_log("zone_exported", {"domain": domain, "provider": provider_id})

    if format == "json":
        records = await adapter.list_records(domain)
        return {
            "format": "json",
            "domain": domain,
            "exported_at": datetime.now().isoformat(),
            "records": records
        }

    return {
        "format": "bind",
        "domain": domain,
        "exported_at": datetime.now().isoformat(),
        "data": zone_data
    }


@app.post("/zones/import", dependencies=[Depends(require_jwt)])
async def import_zone(zone_import: ZoneImport):
    """Import DNS zone from BIND format."""
    provider, adapter = _get_provider(zone_import.provider_id)

    # Parse BIND zone file
    imported = 0
    errors = []

    for line in zone_import.zone_data.split("\n"):
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("$"):
            continue

        # Simple BIND record parser
        parts = line.split()
        if len(parts) >= 4:
            try:
                name = parts[0]
                ttl = int(parts[1]) if parts[1].isdigit() else 300
                idx = 2 if parts[1].isdigit() else 1
                if parts[idx] == "IN":
                    idx += 1
                rtype = parts[idx]
                value = " ".join(parts[idx + 1:])

                record = RecordCreate(
                    type=RecordType(rtype),
                    name=name,
                    value=value,
                    ttl=ttl
                )
                await adapter.create_record(zone_import.domain, record)
                imported += 1
            except Exception as e:
                errors.append(f"Line '{line}': {str(e)}")

    _audit_log("zone_imported", {
        "domain": zone_import.domain,
        "provider": zone_import.provider_id,
        "records_imported": imported,
        "errors": len(errors)
    })

    return {
        "success": imported > 0,
        "domain": zone_import.domain,
        "imported": imported,
        "errors": errors
    }


# ===========================================================================
# Audit Logs
# ===========================================================================

@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_audit_logs(
    limit: int = Query(default=100, le=1000),
    action: Optional[str] = None,
    since: Optional[str] = None
):
    """Get audit logs."""
    logs = []

    try:
        if AUDIT_LOG_FILE.exists():
            with open(AUDIT_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if action and entry.get("action") != action:
                            continue
                        if since and entry.get("timestamp", "") < since:
                            continue
                        logs.append(entry)
                    except json.JSONDecodeError:
                        continue
    except IOError:
        pass

    # Return most recent first
    logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    return {"logs": logs, "total": len(logs)}


# ===========================================================================
# Summary
# ===========================================================================

@app.get("/summary", dependencies=[Depends(require_jwt)])
async def get_summary():
    """Get DNS provider summary."""
    providers = _load_json(PROVIDERS_FILE, {"providers": []})
    all_providers = providers.get("providers", [])

    # Count domains from cache
    cache = _load_json(CACHE_FILE, {"domains": {}})
    total_domains = sum(len(domains) for domains in cache.get("domains", {}).values())

    # Recent logs
    recent_logs = []
    try:
        if AUDIT_LOG_FILE.exists():
            with open(AUDIT_LOG_FILE, "r") as f:
                lines = f.readlines()[-10:]
                for line in reversed(lines):
                    try:
                        recent_logs.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    except IOError:
        pass

    return {
        "providers": {
            "total": len(all_providers),
            "active": sum(1 for p in all_providers if p.get("enabled", True)),
            "by_type": {
                "cloudflare": sum(1 for p in all_providers if p.get("provider") == "cloudflare"),
                "gandi": sum(1 for p in all_providers if p.get("provider") == "gandi"),
                "ovh": sum(1 for p in all_providers if p.get("provider") == "ovh"),
                "route53": sum(1 for p in all_providers if p.get("provider") == "route53")
            }
        },
        "domains": total_domains,
        "recent_activity": recent_logs[:5],
        "cache_updated": cache.get("updated"),
        "timestamp": datetime.now().isoformat()
    }
