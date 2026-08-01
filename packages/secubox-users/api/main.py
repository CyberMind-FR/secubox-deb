#!/usr/bin/env python3
"""
SecuBox Users API v1.3.0 — Unified Identity Management with RBAC
Roles, Permissions, Access Control Lists, and Active Sessions
"""
import subprocess
import json
import httpx
import logging
import os
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Any

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt
    from secubox_core.config import get_config
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}
    def get_config(name):
        return {}

from . import engine as _engine_mod

app = FastAPI(
    title="SecuBox Users API",
    description="Unified Identity Management with RBAC",
    version="1.3.0",
    docs_url="/docs",
    redoc_url=None
)

config = get_config("users") if callable(get_config) else {}
USERSCTL = "/usr/sbin/usersctl"
USERS_FILE = os.environ.get("USERS_FILE", "/etc/secubox/users.json")
ROLES_FILE = os.environ.get("ROLES_FILE", "/etc/secubox/roles.json")
from .redact import redact_user  # expurgation des secrets (module dédié, testable seul)

SERVICES = ["nextcloud", "gitea", "email", "matrix", "jellyfin", "peertube", "jabber"]
# YaCy has a single admin account (no per-user accounts), so its password is
# synced from exactly one SecuBox user: the master "admin". Changing that user's
# password propagates to YaCy when the module is installed and active.
YACY_SYNC_USER = "admin"

_log = logging.getLogger("secubox.users")
SESSIONS_FILE = os.environ.get("SECUBOX_AUTH_SESSIONS", "/var/lib/secubox/auth/sessions.json")

# Single engine instance — all mutations go through here
_engine = _engine_mod.Engine(users_path=Path(USERS_FILE))

# ══════════════════════════════════════════════════════════════════
# Default Permissions & Roles
# ══════════════════════════════════════════════════════════════════

# Available permissions in the system
PERMISSIONS = {
    # User management
    "users.view": "View user list",
    "users.create": "Create new users",
    "users.edit": "Edit existing users",
    "users.delete": "Delete users",
    "users.password": "Reset user passwords",
    # Role management
    "roles.view": "View roles",
    "roles.create": "Create roles",
    "roles.edit": "Edit roles",
    "roles.delete": "Delete roles",
    "roles.assign": "Assign roles to users",
    # Group management
    "groups.view": "View groups",
    "groups.create": "Create groups",
    "groups.edit": "Edit groups",
    "groups.delete": "Delete groups",
    "groups.members": "Manage group members",
    # Service access
    "services.view": "View services status",
    "services.manage": "Manage service access",
    "services.provision": "Provision users to services",
    # System
    "system.view": "View system status",
    "system.config": "Modify system configuration",
    "system.audit": "View audit logs",
    "system.export": "Export data",
    "system.import": "Import data",
    # Module-specific
    "dashboard.view": "Access dashboard",
    "security.view": "View security modules",
    "security.manage": "Manage security settings",
    "network.view": "View network modules",
    "network.manage": "Manage network settings",
}

# Default roles
DEFAULT_ROLES = [
    {
        "id": "admin",
        "name": "Administrator",
        "description": "Full system access",
        "permissions": list(PERMISSIONS.keys()),
        "builtin": True,
        "color": "#ff4466"
    },
    {
        "id": "operator",
        "name": "Operator",
        "description": "Manage users and services",
        "permissions": [
            "users.view", "users.create", "users.edit", "users.password",
            "groups.view", "groups.members",
            "services.view", "services.manage",
            "system.view", "dashboard.view",
            "security.view", "network.view"
        ],
        "builtin": True,
        "color": "#ffaa33"
    },
    {
        "id": "user",
        "name": "User",
        "description": "Basic user access",
        "permissions": [
            "dashboard.view", "services.view", "system.view"
        ],
        "builtin": True,
        "color": "#33ff66"
    },
    {
        "id": "guest",
        "name": "Guest",
        "description": "Read-only access",
        "permissions": ["dashboard.view"],
        "builtin": True,
        "color": "#888888"
    }
]

# ══════════════════════════════════════════════════════════════════
# Models
# ══════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    services: List[str] = []

    @validator('username')
    def validate_username(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if not v.isalnum() and '_' not in v and '-' not in v:
            raise ValueError('Username can only contain letters, numbers, _ and -')
        return v.lower()

class UserUpdate(BaseModel):
    email: Optional[str] = None
    enabled: Optional[bool] = None
    services: Optional[List[str]] = None

class PasswordChange(BaseModel):
    password: str

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    permissions: List[str] = []

class RoleCreate(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    permissions: List[str] = []
    color: Optional[str] = "#33ff66"

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    color: Optional[str] = None

class UserRoleAssign(BaseModel):
    roles: List[str]

class ACLEntry(BaseModel):
    resource: str
    permissions: List[str]

# ══════════════════════════════════════════════════════════════════
# Status Cache — Double-buffer pre-cache for instant responses
# ══════════════════════════════════════════════════════════════════
import asyncio
import time
import threading
from pathlib import Path

CACHE_DIR = Path("/var/cache/secubox/users")
STATUS_CACHE_FILE = CACHE_DIR / "status.json"
_status_cache: Dict[str, Any] = {}
_status_cache_lock = threading.Lock()
_cache_refresh_task = None


def _compute_status_sync() -> Dict[str, Any]:
    """Compute users status (synchronous, for background refresh)."""
    try:
        result = subprocess.run(
            [USERSCTL, "status", "--json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            data["cached_at"] = time.time()
            return data
    except Exception:
        pass

    # Fallback: basic status from files
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            users = json.loads(Path(USERS_FILE).read_text())
        except Exception:
            pass

    return {
        "user_count": len(users.get("users", [])),
        "service_count": len(SERVICES),
        "cached_at": time.time(),
    }


def _refresh_status_cache():
    """Refresh status cache (called from background task)."""
    global _status_cache
    try:
        status_data = _compute_status_sync()
        with _status_cache_lock:
            _status_cache = status_data
        # Persist to file
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            STATUS_CACHE_FILE.write_text(json.dumps(status_data))
        except Exception:
            pass
    except Exception:
        pass


def _load_status_cache():
    """Load status cache from file for fast startup."""
    global _status_cache
    if STATUS_CACHE_FILE.exists():
        try:
            _status_cache = json.loads(STATUS_CACHE_FILE.read_text())
        except Exception:
            pass


async def _periodic_status_refresh():
    """Refresh status cache every 60 seconds."""
    while True:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _refresh_status_cache)
        except Exception:
            pass
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup_event():
    """Start background cache refresh."""
    global _cache_refresh_task
    _load_status_cache()
    _cache_refresh_task = asyncio.create_task(_periodic_status_refresh())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background cache refresh."""
    global _cache_refresh_task
    if _cache_refresh_task:
        _cache_refresh_task.cancel()


# ══════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════

def run_usersctl(*args, parse_json=False):
    """Run usersctl command."""
    cmd = [USERSCTL] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if parse_json and result.returncode == 0:
            return json.loads(result.stdout)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
    except json.JSONDecodeError:
        return {"success": True, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

def load_users() -> dict:
    """Load users via engine (read-only helper for query endpoints)."""
    return _engine._load()

def save_users(data: dict):
    """Atomic save via engine. Mutations should use _engine.* methods directly."""
    _engine._save(data)

def check_service(name: str) -> bool:
    """Check if a service is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", f"secubox-{name}"],
            capture_output=True, text=True
        )
        return result.stdout.strip() == "active"
    except:
        return False

def get_service_ctl(name: str) -> Optional[str]:
    """Get service controller path."""
    ctl = f"/usr/sbin/{name}ctl"
    return ctl if os.path.exists(ctl) else None


def _yacy_available() -> bool:
    """True when the YaCy module is installed and its host service is active."""
    if not os.path.exists("/usr/sbin/yacyctl"):
        return False
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "--quiet", "secubox-yacy.service"],
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _sync_yacy_admin_password(username: str, password: str) -> Optional[bool]:
    """Propagate the master admin user's password to YaCy's single admin account.

    Returns True/False on an attempt, or None when skipped (not the sync user, or
    YaCy not installed/active). The password is handed to `yacyctl set-admin-password`
    over STDIN (never argv) so it cannot leak via ps/sudo logs. yacyctl needs root
    (secret file + lxc-attach); the secubox user is granted exactly this one command
    via secubox-yacy's sudoers drop-in.

    Runtime requirement: this uses `sudo`, which is neutralized by
    `NoNewPrivileges=true` (the kernel drops the setuid bit regardless of sudoers).
    It therefore only elevates when secubox-users runs with NNP disabled — which is
    the case when the module is served in-process by secubox-aggregator
    (NoNewPrivileges=no). On a hardened standalone unit the sudo call fails; we log
    it loudly and return False (never a silent success) so the operator sees that
    YaCy was NOT updated.
    """
    if username != YACY_SYNC_USER:
        return None
    if not _yacy_available():
        return None
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/sbin/yacyctl", "set-admin-password"],
            input=password,
            capture_output=True, text=True, timeout=90,
        )
        if r.returncode != 0:
            _log.warning(
                "YaCy admin password sync failed (rc=%s): %s",
                r.returncode, (r.stderr or "").strip()[:300],
            )
            return False
        return True
    except Exception as exc:
        _log.warning("YaCy admin password sync errored: %s", exc)
        return False

def load_roles() -> List[dict]:
    """Load roles from JSON file or return defaults."""
    if os.path.exists(ROLES_FILE):
        try:
            with open(ROLES_FILE) as f:
                data = json.load(f)
                return data.get("roles", DEFAULT_ROLES)
        except:
            pass
    return DEFAULT_ROLES.copy()

def save_roles(roles: List[dict]):
    """Save roles to JSON file."""
    os.makedirs(os.path.dirname(ROLES_FILE), exist_ok=True)
    with open(ROLES_FILE, "w") as f:
        json.dump({"roles": roles, "permissions": PERMISSIONS}, f, indent=2)

def get_user_permissions(username: str) -> List[str]:
    """Get all permissions for a user based on their roles."""
    data = load_users()
    roles = load_roles()
    role_map = {r["id"]: r for r in roles}

    for user in data.get("users", []):
        if user.get("username") == username:
            user_roles = user.get("roles", ["user"])
            all_perms = set()
            for role_id in user_roles:
                if role_id in role_map:
                    all_perms.update(role_map[role_id].get("permissions", []))
            return list(all_perms)
    return []

def user_has_permission(username: str, permission: str) -> bool:
    """Check if user has a specific permission."""
    perms = get_user_permissions(username)
    return permission in perms or "admin" in perms


def require_permission(permission: str, allow_self_for_param: str = ""):
    """FastAPI dependency factory: requires the JWT subject to have `permission`,
    OR — if `allow_self_for_param` is set — the URL path param of that name
    to equal the JWT subject (`sub`)."""
    async def _check(
        request: Request,
        creds=Depends(require_jwt),
    ):
        # creds is the decoded JWT payload (dict with 'sub' etc.)
        subject = creds.get("sub", "") if isinstance(creds, dict) else "admin"
        if allow_self_for_param:
            # FastAPI provides path params via request.path_params
            target = request.path_params.get(allow_self_for_param, "")
            if target and target == subject:
                return creds
        if user_has_permission(subject, permission):
            return creds
        raise HTTPException(status_code=403, detail=f"Permission requise : {permission}")
    return _check


# ══════════════════════════════════════════════════════════════════
# Public Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/status")
async def get_status():
    """Get users system status. Returns cached data instantly."""
    # Return from cache (instant)
    if _status_cache:
        return _status_cache

    # Fallback: file cache
    if STATUS_CACHE_FILE.exists():
        try:
            return json.loads(STATUS_CACHE_FILE.read_text())
        except Exception:
            pass

    # Last resort: compute (first request only)
    return _compute_status_sync()

@app.get("/services")
async def list_services():
    """List available services and their status."""
    service_status = {}
    for svc in SERVICES:
        ctl = get_service_ctl(svc)
        service_status[svc] = {
            "running": check_service(svc),
            "ctl_available": ctl is not None,
            "icon": {
                "nextcloud": "cloud",
                "gitea": "git-branch",
                "email": "mail",
                "matrix": "message-square",
                "jellyfin": "film",
                "peertube": "video",
                "jabber": "message-circle"
            }.get(svc, "box")
        }
    return {"services": service_status}

@app.get("/components")
async def get_components():
    """Get components status."""
    return run_usersctl("components", parse_json=True)

@app.get("/access")
async def get_access():
    """Get access information."""
    return run_usersctl("access", parse_json=True)

# ══════════════════════════════════════════════════════════════════
# Protected User Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List all users (redacted — never ships hashes or TOTP secrets)."""
    data = load_users()
    users = [redact_user(u) for u in data.get("users", [])]
    return {"users": users, "total": len(users)}

@app.get("/user/{username}", dependencies=[Depends(require_jwt)])
async def get_user(username: str):
    """Get user details."""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            out = redact_user(user)
            # Add service status
            out["service_status"] = {}
            for svc in user.get("services", []):
                out["service_status"][svc] = check_service(svc)
            return out
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/user", dependencies=[Depends(require_jwt)])
def create_user(user: UserCreate):
    """Create a new user and provision to services."""
    # Delegate identity creation to engine.
    # The legacy API role "user" maps to engine role "viewer" (least privilege).
    engine_role = "viewer"
    try:
        new_user = _engine.create_user(
            user.username,
            email=user.email,
            role=engine_role,
        )
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Provision to external services (password used for service setup only, not stored here)
    provision_results = {}
    for svc in user.services:
        if svc not in SERVICES:
            continue
        ctl = get_service_ctl(svc)
        if ctl:
            try:
                if svc == "nextcloud":
                    result = subprocess.run(
                        [ctl, "occ", "user:add", "--password-from-env", user.username],
                        input=user.password,
                        capture_output=True, text=True, timeout=30
                    )
                elif svc == "gitea":
                    result = subprocess.run(
                        [ctl, "user", "add", "--username", user.username,
                         "--email", user.email, "--password", user.password],
                        capture_output=True, text=True, timeout=30
                    )
                else:
                    result = subprocess.run(
                        [ctl, "user-add", user.username, user.email, user.password],
                        capture_output=True, text=True, timeout=30
                    )
                provision_results[svc] = result.returncode == 0
            except Exception:
                provision_results[svc] = False
        else:
            provision_results[svc] = False

    # YaCy single-admin sync (only fires for the master 'admin' user).
    yacy_synced = _sync_yacy_admin_password(user.username, user.password)
    if yacy_synced is not None:
        provision_results["yacy"] = yacy_synced

    # Persist services list via engine's atomic I/O
    if user.services:
        doc = _engine._load()
        for u in doc.get("users", []):
            if u.get("username") == user.username:
                u["services"] = [s for s in user.services if s in SERVICES]
                u["provision_results"] = provision_results
                break
        _engine._save(doc)
        new_user = _engine.get_user(user.username) or new_user

    return {"success": True, "user": new_user, "provision_results": provision_results}

@app.put("/user/{username}", dependencies=[Depends(require_jwt)])
async def update_user(username: str, update: UserUpdate):
    """Update user."""
    # For the enabled flag, delegate to engine to get session revocation + audit
    if update.enabled is not None:
        try:
            if update.enabled:
                _engine.enable_user(username)
            else:
                _engine.disable_user(username)
        except _engine_mod.EngineError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    # For email and services, update via engine's atomic I/O
    if update.email is not None or update.services is not None:
        doc = _engine._load()
        found = False
        for user in doc.get("users", []):
            if user.get("username") == username:
                found = True
                if update.email is not None:
                    user["email"] = update.email
                if update.services is not None:
                    user["services"] = update.services
                    user["updated"] = datetime.now().isoformat()
                break
        if not found:
            raise HTTPException(status_code=404, detail="User not found")
        _engine._save(doc)

    user_record = _engine.get_user(username)
    if not user_record:
        raise HTTPException(status_code=404, detail="User not found")
    return {"success": True, "user": user_record}


@app.post("/user/{username}/disable", dependencies=[Depends(require_permission("users.edit"))])
async def disable_user(username: str):
    """Disable user and revoke their sessions."""
    try:
        revoked = _engine.disable_user(username)
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True, "revoked_sessions": revoked}


@app.post("/user/{username}/enable", dependencies=[Depends(require_permission("users.edit"))])
async def enable_user(username: str):
    """Re-enable a previously disabled user."""
    try:
        _engine.enable_user(username)
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True}

@app.delete("/user/{username}", dependencies=[Depends(require_jwt)])
def delete_user(username: str):
    """Delete user and deprovision from services."""
    # Read services before deleting (engine will remove the record)
    user_record = _engine.get_user(username)
    if not user_record:
        raise HTTPException(status_code=404, detail="User not found")

    # Deprovision from external services
    deprovision_results = {}
    for svc in user_record.get("services", []):
        ctl = get_service_ctl(svc)
        if ctl:
            try:
                if svc == "nextcloud":
                    result = subprocess.run(
                        [ctl, "occ", "user:delete", username],
                        capture_output=True, text=True, timeout=30
                    )
                elif svc == "gitea":
                    result = subprocess.run(
                        [ctl, "user", "delete", "--username", username],
                        capture_output=True, text=True, timeout=30
                    )
                else:
                    result = subprocess.run(
                        [ctl, "user-del", username],
                        capture_output=True, text=True, timeout=30
                    )
                deprovision_results[svc] = result.returncode == 0
            except Exception:
                deprovision_results[svc] = False

    # Delegate deletion to engine
    try:
        _engine.delete_user(username)
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {"success": True, "deprovision_results": deprovision_results}

@app.post("/user/{username}/sync", dependencies=[Depends(require_jwt)])
async def sync_user(username: str):
    """Sync user to all their services."""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            results = {}
            for svc in user.get("services", []):
                results[svc] = check_service(svc)
            return {"success": True, "sync_results": results}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/user/{username}/password", dependencies=[Depends(require_permission("users.password", allow_self_for_param="username"))])
def change_password(username: str, pwd: PasswordChange):
    """Change user password (admin path — caller holds users.password permission).
    Sets the internal password hash via engine and propagates to external services."""
    user_record = _engine.get_user(username)
    if not user_record:
        raise HTTPException(status_code=404, detail="User not found")

    # Delegate hash storage to engine
    try:
        _engine.set_password(username, pwd.password)
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Propagate to external services
    results = {}
    for svc in user_record.get("services", []):
        ctl = get_service_ctl(svc)
        if ctl:
            try:
                if svc == "nextcloud":
                    result = subprocess.run(
                        [ctl, "occ", "user:resetpassword", "--password-from-env", username],
                        input=pwd.password,
                        capture_output=True, text=True, timeout=30
                    )
                elif svc == "gitea":
                    result = subprocess.run(
                        [ctl, "admin", "user", "change-password",
                         "--username", username, "--password", pwd.password],
                        capture_output=True, text=True, timeout=30
                    )
                else:
                    result = subprocess.run(
                        [ctl, "user-passwd", username, pwd.password],
                        capture_output=True, text=True, timeout=30
                    )
                results[svc] = result.returncode == 0
            except Exception:
                results[svc] = False

    # YaCy has a single admin account, synced from the master 'admin' user only.
    # Independent of the per-user services list above.
    yacy_synced = _sync_yacy_admin_password(username, pwd.password)
    if yacy_synced is not None:
        results["yacy"] = yacy_synced

    return {"success": True, "password_results": results}


# ══════════════════════════════════════════════════════════════════
# TOTP Admin Endpoints
# ══════════════════════════════════════════════════════════════════

@app.post("/user/{username}/totp/disable", dependencies=[Depends(require_permission("users.edit"))])
async def disable_user_totp(username: str):
    """Admin: disable TOTP for a user (clears secret and backup codes)."""
    try:
        _engine.disable_totp(username)
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True}


@app.post("/user/{username}/totp/backup-codes", dependencies=[Depends(require_permission("users.edit", allow_self_for_param="username"))])
async def regen_backup_codes(username: str):
    """Admin: regenerate TOTP backup codes for a user (returns plaintext — shown once)."""
    try:
        codes = _engine.regenerate_backup_codes(username)
    except _engine_mod.EngineError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"backup_codes": codes}


# ══════════════════════════════════════════════════════════════════
# Per-User Session Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/user/{username}/sessions", dependencies=[Depends(require_permission("users.view", allow_self_for_param="username"))])
async def list_user_sessions(username: str):
    """List active sessions for a specific user."""
    rows: list = []
    sessions_path = Path(SESSIONS_FILE)
    try:
        data = json.loads(sessions_path.read_text())
        if isinstance(data, list):
            rows = data
        else:
            rows = data.get("sessions", [])
    except (FileNotFoundError, json.JSONDecodeError):
        rows = []
    return [r for r in rows if r.get("username") == username or r.get("sub") == username]


@app.post("/user/{username}/sessions/revoke", dependencies=[Depends(require_permission("users.edit", allow_self_for_param="username"))])
async def revoke_user_sessions(username: str):
    """Revoke all active sessions for a specific user."""
    revoked = _engine.revoke_sessions(username)
    return {"revoked": revoked}


# ══════════════════════════════════════════════════════════════════
# Group Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/groups", dependencies=[Depends(require_jwt)])
async def list_groups():
    """List all groups."""
    data = load_users()
    return {"groups": data.get("groups", [])}

@app.post("/group", dependencies=[Depends(require_jwt)])
async def create_group(group: GroupCreate):
    """Create a new group."""
    doc = _engine._load()

    for g in doc.get("groups", []):
        if g.get("name") == group.name:
            raise HTTPException(status_code=400, detail="Group already exists")

    new_group = {
        "name": group.name,
        "description": group.description,
        "permissions": group.permissions,
        "members": [],
        "created": datetime.now().isoformat()
    }
    doc.setdefault("groups", []).append(new_group)
    _engine._save(doc)

    return {"success": True, "group": new_group}

@app.delete("/group/{name}", dependencies=[Depends(require_jwt)])
async def delete_group(name: str):
    """Delete a group."""
    doc = _engine._load()
    for i, group in enumerate(doc.get("groups", [])):
        if group.get("name") == name:
            doc["groups"].pop(i)
            _engine._save(doc)
            return {"success": True}
    raise HTTPException(status_code=404, detail="Group not found")

# ══════════════════════════════════════════════════════════════════
# Role & Permission Endpoints (RBAC)
# ══════════════════════════════════════════════════════════════════

@app.get("/permissions")
async def list_permissions():
    """List all available permissions in the system."""
    return {
        "permissions": [
            {"id": k, "description": v}
            for k, v in PERMISSIONS.items()
        ],
        "categories": {
            "users": [p for p in PERMISSIONS if p.startswith("users.")],
            "roles": [p for p in PERMISSIONS if p.startswith("roles.")],
            "groups": [p for p in PERMISSIONS if p.startswith("groups.")],
            "services": [p for p in PERMISSIONS if p.startswith("services.")],
            "system": [p for p in PERMISSIONS if p.startswith("system.")],
            "modules": [p for p in PERMISSIONS if p.startswith(("dashboard.", "security.", "network."))],
        }
    }

@app.get("/roles")
async def list_roles():
    """List all roles."""
    roles = load_roles()
    return {"roles": roles, "total": len(roles)}

@app.get("/role/{role_id}")
async def get_role(role_id: str):
    """Get role details."""
    roles = load_roles()
    for role in roles:
        if role.get("id") == role_id:
            return role
    raise HTTPException(status_code=404, detail="Role not found")

@app.post("/role", dependencies=[Depends(require_jwt)])
async def create_role(role: RoleCreate):
    """Create a new role."""
    roles = load_roles()

    # Check if role exists
    for r in roles:
        if r.get("id") == role.id:
            raise HTTPException(status_code=400, detail="Role already exists")

    # Validate permissions
    invalid_perms = [p for p in role.permissions if p not in PERMISSIONS]
    if invalid_perms:
        raise HTTPException(status_code=400, detail=f"Invalid permissions: {invalid_perms}")

    new_role = {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "permissions": role.permissions,
        "color": role.color,
        "builtin": False,
        "created": datetime.now().isoformat()
    }
    roles.append(new_role)
    save_roles(roles)

    return {"success": True, "role": new_role}

@app.put("/role/{role_id}", dependencies=[Depends(require_jwt)])
async def update_role(role_id: str, update: RoleUpdate):
    """Update a role."""
    roles = load_roles()

    for role in roles:
        if role.get("id") == role_id:
            if role.get("builtin"):
                raise HTTPException(status_code=403, detail="Cannot modify built-in role")

            if update.name is not None:
                role["name"] = update.name
            if update.description is not None:
                role["description"] = update.description
            if update.permissions is not None:
                # Validate permissions
                invalid_perms = [p for p in update.permissions if p not in PERMISSIONS]
                if invalid_perms:
                    raise HTTPException(status_code=400, detail=f"Invalid permissions: {invalid_perms}")
                role["permissions"] = update.permissions
            if update.color is not None:
                role["color"] = update.color

            role["updated"] = datetime.now().isoformat()
            save_roles(roles)
            return {"success": True, "role": role}

    raise HTTPException(status_code=404, detail="Role not found")

@app.delete("/role/{role_id}", dependencies=[Depends(require_jwt)])
async def delete_role(role_id: str):
    """Delete a role."""
    roles = load_roles()

    for i, role in enumerate(roles):
        if role.get("id") == role_id:
            if role.get("builtin"):
                raise HTTPException(status_code=403, detail="Cannot delete built-in role")
            roles.pop(i)
            save_roles(roles)
            return {"success": True}

    raise HTTPException(status_code=404, detail="Role not found")

@app.get("/user/{username}/roles", dependencies=[Depends(require_jwt)])
async def get_user_roles(username: str):
    """Get roles assigned to a user."""
    data = load_users()
    roles = load_roles()
    role_map = {r["id"]: r for r in roles}

    for user in data.get("users", []):
        if user.get("username") == username:
            user_roles = user.get("roles", ["user"])
            return {
                "username": username,
                "roles": [role_map.get(r, {"id": r, "name": r}) for r in user_roles],
                "role_ids": user_roles
            }
    raise HTTPException(status_code=404, detail="User not found")

@app.put("/user/{username}/roles", dependencies=[Depends(require_jwt)])
async def assign_user_roles(username: str, assignment: UserRoleAssign):
    """Assign roles to a user."""
    roles = load_roles()
    valid_role_ids = {r["id"] for r in roles}

    # Validate role IDs
    invalid_roles = [r for r in assignment.roles if r not in valid_role_ids]
    if invalid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid roles: {invalid_roles}")

    # Use engine's atomic I/O
    doc = _engine._load()
    for user in doc.get("users", []):
        if user.get("username") == username:
            user["roles"] = assignment.roles
            user["roles_updated"] = datetime.now().isoformat()
            _engine._save(doc)
            return {"success": True, "roles": assignment.roles}

    raise HTTPException(status_code=404, detail="User not found")

@app.get("/user/{username}/permissions", dependencies=[Depends(require_jwt)])
async def get_user_permissions_endpoint(username: str):
    """Get all effective permissions for a user."""
    perms = get_user_permissions(username)
    if not perms:
        # Check if user exists
        data = load_users()
        if not any(u.get("username") == username for u in data.get("users", [])):
            raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": username,
        "permissions": perms,
        "permission_details": [
            {"id": p, "description": PERMISSIONS.get(p, "Unknown")}
            for p in perms
        ]
    }

@app.post("/user/{username}/check-permission", dependencies=[Depends(require_jwt)])
async def check_user_permission(username: str, permission: str):
    """Check if a user has a specific permission."""
    has_perm = user_has_permission(username, permission)
    return {
        "username": username,
        "permission": permission,
        "granted": has_perm
    }

# ══════════════════════════════════════════════════════════════════
# ACL Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/acl")
async def get_acl():
    """Get the full Access Control List matrix."""
    data = load_users()
    roles = load_roles()

    acl_matrix = []
    for user in data.get("users", []):
        user_roles = user.get("roles", ["user"])
        user_perms = get_user_permissions(user.get("username", ""))

        acl_matrix.append({
            "username": user.get("username"),
            "email": user.get("email"),
            "enabled": user.get("enabled", True),
            "roles": user_roles,
            "permissions_count": len(user_perms),
            "is_admin": "admin" in user_roles or all(p in user_perms for p in PERMISSIONS.keys())
        })

    return {
        "users": acl_matrix,
        "roles": roles,
        "total_permissions": len(PERMISSIONS)
    }

@app.post("/acl/validate", dependencies=[Depends(require_jwt)])
async def validate_acl(entries: List[ACLEntry]):
    """Validate a list of ACL entries."""
    results = []
    for entry in entries:
        invalid_perms = [p for p in entry.permissions if p not in PERMISSIONS]
        results.append({
            "resource": entry.resource,
            "valid": len(invalid_perms) == 0,
            "invalid_permissions": invalid_perms
        })
    return {"results": results}

# ══════════════════════════════════════════════════════════════════
# Import/Export
# ══════════════════════════════════════════════════════════════════

@app.get("/export", dependencies=[Depends(require_jwt)])
async def export_users():
    """Export all users (redacted).

    This route previously claimed to "remove sensitive data" while dropping only
    `provision_results` — it shipped every password hash and TOTP secret into a
    downloadable file. A comment asserting a guarantee the code does not provide
    is worse than no comment: it stops reviewers from looking. The guarantee now
    lives in redact_user(), which is the single place that decides what a client
    may see.
    """
    data = load_users()
    return {
        "users": [redact_user(u) for u in data.get("users", [])],
        "groups": data.get("groups", []),
    }

@app.post("/import", dependencies=[Depends(require_permission("system.import"))])
async def import_users(file: UploadFile = File(...)):
    """Import users from JSON file. Each row goes through engine.create_user so
    username regex, role enum, and must_change_password defaults are enforced."""
    try:
        content = await file.read()
        import_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    if "users" not in import_data:
        raise HTTPException(status_code=400, detail="Invalid format: missing 'users' key")

    created: list = []
    skipped: list = []
    errors: list = []

    for row in import_data.get("users", []):
        username = row.get("username")
        if not username:
            errors.append({"username": None, "error": "missing username"})
            continue

        # Reject raw password_hash injection — callers must use the engine policy
        if "password_hash" in row:
            errors.append({"username": username, "error": "password_hash injection not allowed; set password via engine"})
            continue

        email = row.get("email")
        role = row.get("role", "viewer")

        try:
            _engine.create_user(username, email=email, role=role)
            created.append(username)
            # If a plaintext password is provided, hash it via engine (validates policy)
            pw = row.get("password")
            if pw:
                _engine.set_password(username, pw)
        except _engine_mod.EngineError as exc:
            err_msg = str(exc)
            # Distinguish "already exists" (skipped) from other engine errors
            if "exists" in err_msg:
                skipped.append(username)
            else:
                errors.append({"username": username, "error": err_msg})
        except Exception as exc:
            # Catch-all so one bad row doesn't break the import
            errors.append({"username": username, "error": f"unexpected: {exc}"})

    return {"created": created, "skipped": skipped, "errors": errors}

# ══════════════════════════════════════════════════════════════════
# Active Sessions
# ══════════════════════════════════════════════════════════════════

@app.get("/sessions", dependencies=[Depends(require_jwt)])
async def get_sessions():
    """Get active user sessions from auth module."""
    sessions = []
    now = int(datetime.now().timestamp())

    # Read sessions from auth module file
    if os.path.exists(SESSIONS_FILE):
        try:
            data = json.loads(Path(SESSIONS_FILE).read_text())
            # Handle both array and object with "sessions" key
            if isinstance(data, list):
                sessions = data
            else:
                sessions = data.get("sessions", [])
            # Filter out expired sessions
            sessions = [s for s in sessions if s.get("expires", 0) > now]
        except Exception:
            pass

    # Enrich with user info
    data = load_users()
    user_map = {u["username"]: u for u in data.get("users", [])}

    enriched = []
    for s in sessions:
        username = s.get("username", s.get("sub", "unknown"))
        user_info = user_map.get(username, {})
        # Handle different timestamp formats
        created = s.get("created", s.get("created_at", s.get("iat", "")))
        expires = s.get("expires", s.get("expires_at", s.get("exp", "")))
        # Convert unix timestamp to ISO if needed
        if isinstance(expires, int):
            expires = datetime.fromtimestamp(expires).isoformat()
        enriched.append({
            "id": s.get("id", s.get("jti", "")),
            "username": username,
            "email": user_info.get("email", ""),
            "ip": s.get("ip", s.get("client_ip", "unknown")),
            "user_agent": (s.get("user_agent", "") or "")[:50],
            "type": s.get("type", "jwt"),
            "created_at": created,
            "expires_at": expires,
            "last_active": s.get("last_active", ""),
            "current": s.get("current", False),
        })

    return {
        "sessions": enriched,
        "total": len(enriched),
        "timestamp": datetime.now().isoformat()
    }


AUTH_SOCKET = "/run/secubox/auth.sock"


def _auth_credentials(request: Request) -> dict:
    """Headers carrying the CALLER's identity, for a call to secubox-auth.

    `POST /revoke_session` requires a JWT and records `by: <sub>` in the audit
    trail, so the revocation must travel under the admin's own credential.
    Anything else would either be an anonymous revocation or force a second
    writer on sessions.json — which #942 forbids: exactly one writer.
    """
    headers = {}
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header
    cookie = request.headers.get("Cookie")
    if cookie:
        headers["Cookie"] = cookie
    return headers


@app.delete("/session/{session_id}", dependencies=[Depends(require_jwt)])
async def revoke_session(session_id: str, request: Request):
    """Revoke a specific session, through the module that owns the store.

    Rewritten in #944. The previous version shelled out to
    `curl -X DELETE .../session/{id}` — a route secubox-auth has never
    exposed (its verb is `POST /revoke_session?session_id=…`), so every call
    got a 404. Worse, success was read off `curl`'s exit status, and `curl -s`
    exits 0 on a 404: the endpoint always answered `success: true` and the UI
    reported "✅ Session revoked" while nothing had happened.
    """
    try:
        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=AUTH_SOCKET), timeout=10.0
        ) as client:
            resp = await client.post(
                "http://localhost/api/v1/auth/revoke_session",
                params={"session_id": session_id},
                headers=_auth_credentials(request),
            )
    except Exception as e:
        _log.warning("revoke_session: auth module unreachable: %s", e)
        raise HTTPException(status_code=502, detail=f"Module auth injoignable : {e}")

    if resp.status_code != 200:
        # Surface the real failure instead of claiming success.
        _log.warning("revoke_session: auth returned %s for %s", resp.status_code, session_id)
        raise HTTPException(
            status_code=resp.status_code,
            detail=f"Le module auth a refusé la révocation (HTTP {resp.status_code})",
        )

    body = resp.json() if resp.content else {}
    if not body.get("success"):
        return {"success": False, "error": body.get("error", "Session introuvable")}
    return {"success": True, "session_id": session_id}


@app.post("/sessions/revoke-all", dependencies=[Depends(require_jwt)])
def revoke_all_sessions():
    """EMERGENCY: Revoke ALL active sessions immediately.
    This is a panic button - all users will be logged out.
    """
    revoked = 0
    errors = []

    # Clear the sessions file
    if os.path.exists(SESSIONS_FILE):
        try:
            # Read current count for reporting
            data = json.loads(Path(SESSIONS_FILE).read_text())
            if isinstance(data, list):
                revoked = len(data)
            else:
                revoked = len(data.get("sessions", []))

            # Write an empty LIST — the store's only shape (#944).
            #
            # This used to write {"sessions": [], "revoked_at": …}. Both
            # secubox-auth and secubox_core.sessions iterate the file as a
            # list; iterating a dict yields its keys, so
            # `any(s.get("id") == jti for s in rows)` raised
            # `AttributeError: 'str' object has no attribute 'get'` — the panic
            # button broke secubox-auth on every authenticated request.
            Path(SESSIONS_FILE).write_text(json.dumps([]))
        except Exception as e:
            errors.append(f"Failed to clear sessions file: {e}")

    # Also try to notify auth module via socket
    try:
        result = subprocess.run(
            ["curl", "-s", "-X", "POST", "--unix-socket", "/run/secubox/auth.sock",
             "http://localhost/sessions/revoke-all"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            errors.append("Auth module notification failed")
    except Exception as e:
        errors.append(f"Auth socket error: {e}")

    return {
        "success": True,
        "revoked": revoked,
        "timestamp": datetime.now().isoformat(),
        "warnings": errors if errors else None
    }


# ══════════════════════════════════════════════════════════════════
# Health Check
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-users", "version": "1.3.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
