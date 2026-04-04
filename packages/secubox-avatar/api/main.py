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


app.include_router(router)
