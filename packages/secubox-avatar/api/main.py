# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-avatar
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Identity and avatar management module for SecuBox services.
"""
import os
import uuid
import shutil
import hashlib
import asyncio
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, EmailStr
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-avatar", version="1.0.0", root_path="/api/v1/avatar")

# Phase 2b/2c (#488/#490) : ingest mitm avatar events + UA/CH device classification
from secubox_core.mitm_ingest import mount_ingest_routes  # noqa: E402
from secubox_core.classifiers import avatar as _avatar_cls  # noqa: E402


def _avatar_enrich(event: dict) -> dict:
    """Phase 2c enrichment : UA + Client Hints -> {device, browser, os, emoji}."""
    ua = event.get("user_agent") or ""
    if not ua:
        return event
    cls = _avatar_cls.classify_user_agent(ua)
    # Augment with Client Hints if present (more reliable than UA spoofing)
    chints = event.get("client_hints") or {}
    if "sec-ch-ua-platform" in chints:
        cls["ch_platform"] = chints["sec-ch-ua-platform"].strip('"')
    if "sec-ch-ua-model" in chints:
        cls["ch_model"] = chints["sec-ch-ua-model"].strip('"')
    event["enriched"] = {
        "device": cls.get("device", "unknown"),
        "device_emoji": cls.get("device_emoji", "❔"),
        "os_label": cls.get("os_label", "?"),
        "browser": cls.get("browser", "unknown"),
        "browser_emoji": cls.get("browser_emoji", "❔"),
        "browser_label": cls.get("browser_label", "?"),
        "ch_platform": cls.get("ch_platform"),
        "ch_model": cls.get("ch_model"),
        "source": "secubox-avatar/classifier",
    }
    return event


mount_ingest_routes(
    app,
    endpoint_path="/fingerprint",
    db_path="/var/lib/secubox/avatar/mitm-ingest.db",
    kind="avatar",
    enrich_hook=_avatar_enrich,
)

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("avatar")

# Configuration
DATA_DIR = Path("/var/lib/secubox/avatar")
IDENTITIES_FILE = DATA_DIR / "identities.json"
IMAGES_DIR = DATA_DIR / "images"
CONFIG_FILE = Path("/etc/secubox/avatar.toml")

# Allowed image formats
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5MB

# Connected services configuration
SERVICES = {
    "gitea": {"name": "Gitea", "icon": "git", "api_endpoint": "/api/v1/user"},
    "nextcloud": {"name": "Nextcloud", "icon": "cloud", "api_endpoint": "/ocs/v1.php/cloud/user"},
    "mail": {"name": "Mail Server", "icon": "mail", "api_endpoint": None},
    "matrix": {"name": "Matrix", "icon": "chat", "api_endpoint": "/_matrix/client/r0/profile"},
    "ldap": {"name": "LDAP Directory", "icon": "users", "api_endpoint": None},
}


# Pydantic Models
class Identity(BaseModel):
    """Identity model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str = Field(..., min_length=2, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=128)
    email: Optional[EmailStr] = None
    avatar_url: Optional[str] = None
    services: List[str] = Field(default_factory=list)
    sync_status: Dict[str, str] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class IdentityCreate(BaseModel):
    """Identity creation request."""
    username: str = Field(..., min_length=2, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=128)
    email: Optional[EmailStr] = None
    services: List[str] = Field(default_factory=list)


class IdentityUpdate(BaseModel):
    """Identity update request."""
    username: Optional[str] = Field(None, min_length=2, max_length=64)
    display_name: Optional[str] = Field(None, min_length=1, max_length=128)
    email: Optional[EmailStr] = None
    services: Optional[List[str]] = None


class SyncRequest(BaseModel):
    """Sync request model."""
    identity_id: str
    services: Optional[List[str]] = None  # None means all configured services


class SyncResult(BaseModel):
    """Sync result model."""
    service: str
    status: str  # success, failed, skipped
    message: Optional[str] = None


def _ensure_dirs():
    """Ensure data directories exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)


def _load_identities() -> Dict[str, Dict[str, Any]]:
    """Load identities from JSON file."""
    _ensure_dirs()
    if IDENTITIES_FILE.exists():
        try:
            data = json.loads(IDENTITIES_FILE.read_text())
            return {item["id"]: item for item in data} if isinstance(data, list) else data
        except Exception as e:
            log.warning("Failed to load identities: %s", e)
    return {}


def _save_identities(identities: Dict[str, Dict[str, Any]]):
    """Save identities to JSON file."""
    _ensure_dirs()
    IDENTITIES_FILE.write_text(json.dumps(list(identities.values()), indent=2))


def _get_avatar_path(identity_id: str, ext: str = ".png") -> Path:
    """Get avatar file path for an identity."""
    return IMAGES_DIR / f"{identity_id}{ext}"


def _find_avatar(identity_id: str) -> Optional[Path]:
    """Find avatar file for an identity (any extension)."""
    _ensure_dirs()
    for ext in ALLOWED_EXTENSIONS:
        path = _get_avatar_path(identity_id, ext)
        if path.exists():
            return path
    return None


def _delete_avatar(identity_id: str):
    """Delete all avatar files for an identity."""
    for ext in ALLOWED_EXTENSIONS:
        path = _get_avatar_path(identity_id, ext)
        if path.exists():
            path.unlink()


async def _sync_to_service(identity: Dict[str, Any], service: str) -> SyncResult:
    """Sync identity to a specific service."""
    if service not in SERVICES:
        return SyncResult(service=service, status="skipped", message="Unknown service")

    service_config = SERVICES[service]

    # Check if service is in identity's configured services
    if service not in identity.get("services", []):
        return SyncResult(service=service, status="skipped", message="Service not configured for this identity")

    try:
        # Load service-specific configuration
        cfg = get_config("avatar")
        service_cfg = cfg.get("services", {}).get(service, {}) if cfg else {}

        if not service_cfg.get("enabled", False):
            return SyncResult(service=service, status="skipped", message="Service not enabled")

        # Service-specific sync logic would go here
        # For now, we simulate a successful sync
        log.info("Syncing identity %s to %s", identity.get("username"), service)

        # In a real implementation, this would make API calls to the service
        # For example:
        # - Gitea: PUT /api/v1/user with display name and avatar
        # - Nextcloud: PUT /ocs/v1.php/cloud/users/{user}
        # - Matrix: PUT /_matrix/client/r0/profile/{userId}/displayname

        return SyncResult(service=service, status="success", message="Synchronized successfully")

    except Exception as e:
        log.error("Sync to %s failed: %s", service, e)
        return SyncResult(service=service, status="failed", message=str(e))


# Health endpoint (public)
@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "avatar", "version": "1.0.0"}


# Identity endpoints
@router.get("/identities")
async def list_identities(user=Depends(require_jwt)):
    """List all identities."""
    identities = _load_identities()
    return {
        "identities": list(identities.values()),
        "count": len(identities),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/identity/{identity_id}")
async def get_identity(identity_id: str, user=Depends(require_jwt)):
    """Get specific identity."""
    identities = _load_identities()
    if identity_id not in identities:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identities[identity_id]


@router.post("/identity")
async def create_identity(data: IdentityCreate, user=Depends(require_jwt)):
    """Create new identity."""
    identities = _load_identities()

    # Check for duplicate username
    for existing in identities.values():
        if existing.get("username") == data.username:
            raise HTTPException(status_code=400, detail="Username already exists")

    identity = Identity(
        username=data.username,
        display_name=data.display_name,
        email=data.email,
        services=data.services
    )

    identity_dict = identity.model_dump()
    identities[identity.id] = identity_dict
    _save_identities(identities)

    log.info("Identity created: %s by %s", identity.username, user.get("sub"))
    return {"success": True, "identity": identity_dict}


@router.put("/identity/{identity_id}")
async def update_identity(identity_id: str, data: IdentityUpdate, user=Depends(require_jwt)):
    """Update identity."""
    identities = _load_identities()
    if identity_id not in identities:
        raise HTTPException(status_code=404, detail="Identity not found")

    identity = identities[identity_id]

    # Check for duplicate username if changing
    if data.username and data.username != identity.get("username"):
        for existing in identities.values():
            if existing.get("id") != identity_id and existing.get("username") == data.username:
                raise HTTPException(status_code=400, detail="Username already exists")

    # Update fields
    if data.username is not None:
        identity["username"] = data.username
    if data.display_name is not None:
        identity["display_name"] = data.display_name
    if data.email is not None:
        identity["email"] = data.email
    if data.services is not None:
        identity["services"] = data.services

    identity["updated_at"] = datetime.now().isoformat()

    _save_identities(identities)

    log.info("Identity updated: %s by %s", identity.get("username"), user.get("sub"))
    return {"success": True, "identity": identity}


@router.delete("/identity/{identity_id}")
async def delete_identity(identity_id: str, user=Depends(require_jwt)):
    """Delete identity."""
    identities = _load_identities()
    if identity_id not in identities:
        raise HTTPException(status_code=404, detail="Identity not found")

    username = identities[identity_id].get("username")
    del identities[identity_id]
    _save_identities(identities)

    # Delete avatar files
    _delete_avatar(identity_id)

    log.info("Identity deleted: %s by %s", username, user.get("sub"))
    return {"success": True, "message": f"Identity {username} deleted"}


# Avatar endpoints
@router.post("/avatar/upload")
async def upload_avatar(
    identity_id: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(require_jwt)
):
    """Upload avatar image."""
    identities = _load_identities()
    if identity_id not in identities:
        raise HTTPException(status_code=404, detail="Identity not found")

    # Validate file extension
    ext = Path(file.filename).suffix.lower() if file.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Read and validate file size
    content = await file.read()
    if len(content) > MAX_IMAGE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 5MB)")

    # Delete any existing avatar
    _delete_avatar(identity_id)

    # Save new avatar
    _ensure_dirs()
    avatar_path = _get_avatar_path(identity_id, ext)
    avatar_path.write_bytes(content)

    # Update identity with avatar URL
    avatar_url = f"/api/v1/avatar/avatar/{identity_id}"
    identities[identity_id]["avatar_url"] = avatar_url
    identities[identity_id]["updated_at"] = datetime.now().isoformat()
    _save_identities(identities)

    log.info("Avatar uploaded for %s by %s", identities[identity_id].get("username"), user.get("sub"))
    return {"success": True, "avatar_url": avatar_url}


@router.get("/avatar/{identity_id}")
async def get_avatar(identity_id: str):
    """Get avatar image. Public endpoint for displaying avatars."""
    avatar_path = _find_avatar(identity_id)
    if not avatar_path:
        raise HTTPException(status_code=404, detail="Avatar not found")

    # Determine media type
    ext = avatar_path.suffix.lower()
    media_types = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp"
    }
    media_type = media_types.get(ext, "application/octet-stream")

    return FileResponse(avatar_path, media_type=media_type)


@router.delete("/avatar/{identity_id}")
async def delete_avatar(identity_id: str, user=Depends(require_jwt)):
    """Delete avatar image."""
    identities = _load_identities()
    if identity_id not in identities:
        raise HTTPException(status_code=404, detail="Identity not found")

    _delete_avatar(identity_id)

    # Clear avatar URL
    identities[identity_id]["avatar_url"] = None
    identities[identity_id]["updated_at"] = datetime.now().isoformat()
    _save_identities(identities)

    log.info("Avatar deleted for %s by %s", identities[identity_id].get("username"), user.get("sub"))
    return {"success": True, "message": "Avatar deleted"}


# Services endpoints
@router.get("/services")
async def list_services(user=Depends(require_jwt)):
    """List available connected services."""
    cfg = get_config("avatar")
    services_cfg = cfg.get("services", {}) if cfg else {}

    result = []
    for service_id, service_info in SERVICES.items():
        service_cfg = services_cfg.get(service_id, {})
        result.append({
            "id": service_id,
            "name": service_info["name"],
            "icon": service_info["icon"],
            "enabled": service_cfg.get("enabled", False),
            "configured": bool(service_cfg.get("url"))
        })

    return {"services": result, "timestamp": datetime.now().isoformat()}


@router.post("/sync")
async def sync_identity(request: SyncRequest, user=Depends(require_jwt)):
    """Sync identity to connected services."""
    identities = _load_identities()
    if request.identity_id not in identities:
        raise HTTPException(status_code=404, detail="Identity not found")

    identity = identities[request.identity_id]
    services_to_sync = request.services or identity.get("services", [])

    results = []
    for service in services_to_sync:
        result = await _sync_to_service(identity, service)
        results.append(result.model_dump())

        # Update sync status in identity
        identity.setdefault("sync_status", {})[service] = {
            "status": result.status,
            "last_sync": datetime.now().isoformat(),
            "message": result.message
        }

    identity["updated_at"] = datetime.now().isoformat()
    _save_identities(identities)

    log.info("Sync completed for %s: %d services", identity.get("username"), len(results))
    return {
        "success": True,
        "results": results,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/summary")
async def summary():
    """Get avatar module summary for dashboard widget."""
    identities = _load_identities()

    # Count identities with avatars
    with_avatars = sum(1 for i in identities.values() if i.get("avatar_url"))

    # Count configured services
    cfg = get_config("avatar")
    services_cfg = cfg.get("services", {}) if cfg else {}
    enabled_services = sum(1 for s in services_cfg.values() if s.get("enabled", False))

    return {
        "total_identities": len(identities),
        "with_avatars": with_avatars,
        "enabled_services": enabled_services,
        "timestamp": datetime.now().isoformat()
    }


# ══════════════════════════════════════════════════════════════════
# Credential broker — peek / poke (Punk-Exposure model) — #402
# Share browser-side authentication (cookies, PO tokens) with backend services
# via the SecuBox Companion extension. The browser passes YouTube's BotGuard,
# so it can hand PeerTube fresh cookies/tokens that the server can't mint.
# ══════════════════════════════════════════════════════════════════

CRED_STATE_FILE = DATA_DIR / "cred-state.json"
_PEERTUBECTL = "/usr/sbin/peertubectl"
_PT_COOKIE_SPOOL = "/run/secubox/peertube-yt-cookies.txt"

# Credential-shareable services: browser domain → how to apply it.
CRED_SERVICES = {
    "youtube": {
        "label": "YouTube → PeerTube import",
        "target": "peertube",
        "cookie_domain": "youtube.com",
        "accepts": ["cookies", "po_token", "visitor_data"],
    },
}


class CredPoke(BaseModel):
    """Browser-supplied credentials pushed by the extension."""
    cookies: Optional[str] = None        # Netscape cookies.txt body
    po_token: Optional[str] = None       # web GVS PO token (experimental)
    visitor_data: Optional[str] = None   # paired with po_token


def _load_cred_state() -> Dict[str, Any]:
    if CRED_STATE_FILE.exists():
        try:
            return json.loads(CRED_STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_cred_state(state: Dict[str, Any]):
    _ensure_dirs()
    CRED_STATE_FILE.write_text(json.dumps(state, indent=2))


def _apply_youtube(poke: CredPoke) -> Dict[str, str]:
    """Apply YouTube creds to PeerTube. The avatar daemon stays UNPRIVILEGED
    (CSPN): it writes the cookies to the spool and the root
    peertube-cookie-install.path/.service installs them into the LXC (#407) —
    no sudo, NoNewPrivileges intact. PO-token application is experimental and
    pending the browser capture + a peertubectl verb (#401 P4)."""
    results: Dict[str, str] = {}
    if poke.cookies:
        try:
            with open(_PT_COOKIE_SPOOL, "w") as f:
                f.write(poke.cookies)
            os.chmod(_PT_COOKIE_SPOOL, 0o600)
            results["cookies"] = "queued"   # root path-unit installs + restarts PeerTube
        except Exception as e:
            results["cookies"] = f"error: {e}"
    if poke.po_token:
        results["po_token"] = "pending"     # P4: browser PO-token relay not wired yet
    return results


@router.get("/cred/peek")
async def cred_peek(user=Depends(require_jwt)):
    """Peek: what credentials each service accepts + current state."""
    state = _load_cred_state()
    out = []
    for svc, meta in CRED_SERVICES.items():
        st = state.get(svc, {})
        out.append({
            "service": svc,
            "label": meta["label"],
            "target": meta["target"],
            "cookie_domain": meta["cookie_domain"],
            "accepts": meta["accepts"],
            "last_poke": st.get("last_poke"),
            "last_result": st.get("last_result"),
            "has_cookies": st.get("has_cookies", False),
            "has_po_token": st.get("has_po_token", False),
        })
    return {"services": out}


@router.post("/cred/poke/{service}")
async def cred_poke(service: str, poke: CredPoke, user=Depends(require_jwt)):
    """Poke: apply browser-supplied credentials to a service's target."""
    meta = CRED_SERVICES.get(service)
    if not meta:
        raise HTTPException(status_code=404, detail=f"unknown credential service: {service}")
    if not (poke.cookies or poke.po_token):
        raise HTTPException(status_code=400, detail="nothing to poke (cookies/po_token empty)")
    if service == "youtube":
        results = _apply_youtube(poke)
    else:
        raise HTTPException(status_code=501, detail=f"no handler for {service}")
    log.info("cred poke %s by %s -> %s", service, user.get("sub", "?"), results)
    state = _load_cred_state()
    state[service] = {
        "last_poke": datetime.now().isoformat(),
        "last_result": results,
        "has_cookies": bool(poke.cookies),
        "has_po_token": bool(poke.po_token),
        "by": user.get("sub", "?"),
    }
    _save_cred_state(state)
    # Cookies are the primary credential ("queued" = handed to the root installer);
    # an experimental po_token "pending" must not fail the poke.
    cstat = results.get("cookies")
    ok = cstat in ("ok", "queued") or (not poke.cookies and results.get("po_token") == "ok")
    return {"success": ok, "service": service, "results": results}


# ══════════════════════════════════════════════════════════════════
# Session vault — client-encrypted browser-session backup + profiles (#409)
# The SecuBox keeps + protects these backups: the EXTENSION encrypts cookies
# with the operator's passphrase (WebCrypto AES-GCM) BEFORE upload, so this
# module stores OPAQUE ciphertext only — never plaintext, never the key. A
# breach yields unreadable blobs. LAN/SSO-gated; nothing leaves the box.
# ══════════════════════════════════════════════════════════════════

VAULT_DIR = DATA_DIR / "vault"


class VaultBackup(BaseModel):
    """An encrypted session backup pushed by the extension."""
    profile: str = Field("default", min_length=1, max_length=64)
    domain: str = Field(..., min_length=1, max_length=128)
    blob: str = Field(..., min_length=1)         # base64 AES-GCM ciphertext
    iv: str = Field(..., min_length=1)           # base64 IV/nonce
    meta: Optional[Dict[str, Any]] = None        # non-secret: cookie count, captured_at…


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)[:128]


def _vault_path(profile: str, domain: str) -> Path:
    return VAULT_DIR / _safe(profile) / f"{_safe(domain)}.json"


@router.post("/vault/backup")
async def vault_backup(b: VaultBackup, user=Depends(require_jwt)):
    """Store an encrypted session backup (ciphertext only)."""
    p = _vault_path(b.profile, b.domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(VAULT_DIR, 0o700)
        os.chmod(p.parent, 0o700)
    except OSError:
        pass
    p.write_text(json.dumps({
        "profile": b.profile, "domain": b.domain,
        "blob": b.blob, "iv": b.iv, "meta": b.meta or {},
        "saved_at": datetime.now().isoformat(), "by": user.get("sub", "?"),
    }))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    log.info("vault backup %s/%s by %s", b.profile, b.domain, user.get("sub", "?"))
    return {"success": True, "profile": b.profile, "domain": b.domain}


@router.get("/vault/list")
async def vault_list(user=Depends(require_jwt)):
    """List backups (metadata only — never the ciphertext)."""
    out, profiles = [], set()
    if VAULT_DIR.exists():
        for prof in sorted(VAULT_DIR.iterdir()):
            if not prof.is_dir():
                continue
            for f in sorted(prof.glob("*.json")):
                try:
                    d = json.loads(f.read_text())
                    profiles.add(d.get("profile", prof.name))
                    out.append({"profile": d.get("profile"), "domain": d.get("domain"),
                                "meta": d.get("meta", {}), "saved_at": d.get("saved_at")})
                except Exception:
                    pass
    return {"backups": out, "profiles": sorted(profiles)}


@router.get("/vault/restore/{profile}/{domain}")
async def vault_restore(profile: str, domain: str, user=Depends(require_jwt)):
    """Return the encrypted blob for the extension to decrypt + apply locally."""
    p = _vault_path(profile, domain)
    if not p.exists():
        raise HTTPException(status_code=404, detail="no such backup")
    d = json.loads(p.read_text())
    return {"profile": d["profile"], "domain": d["domain"],
            "blob": d["blob"], "iv": d["iv"], "meta": d.get("meta", {})}


@router.delete("/vault/{profile}/{domain}")
async def vault_delete(profile: str, domain: str, user=Depends(require_jwt)):
    p = _vault_path(profile, domain)
    if p.exists():
        p.unlink()
    log.info("vault delete %s/%s by %s", profile, domain, user.get("sub", "?"))
    return {"success": True}


app.include_router(router)
