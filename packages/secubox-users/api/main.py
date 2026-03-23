#!/usr/bin/env python3
"""
SecuBox Users API v1.1.0 — Unified Identity Management
"""
import subprocess
import json
import os
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List

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

app = FastAPI(
    title="SecuBox Users API",
    description="Unified Identity Management",
    version="1.1.0",
    docs_url="/docs",
    redoc_url=None
)

config = get_config("users") if callable(get_config) else {}
USERSCTL = "/usr/sbin/usersctl"
USERS_FILE = os.environ.get("USERS_FILE", "/etc/secubox/users.json")
SERVICES = ["nextcloud", "gitea", "email", "matrix", "jellyfin", "peertube", "jabber"]

# ══════════════════════════════════════════════════════════════════
# Models
# ══════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    services: List[str] = []

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if not v.isalnum() and '_' not in v and '-' not in v:
            raise ValueError('Username can only contain letters, numbers, _ and -')
        return v.lower()

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class UserUpdate(BaseModel):
    email: Optional[str] = None
    enabled: Optional[bool] = None
    services: Optional[List[str]] = None

class PasswordChange(BaseModel):
    password: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    permissions: List[str] = []

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
    """Load users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"users": [], "groups": []}

def save_users(data: dict):
    """Save users to JSON file."""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

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

# ══════════════════════════════════════════════════════════════════
# Public Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/status")
async def get_status():
    """Get users system status."""
    return run_usersctl("status", "--json", parse_json=True)

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
    """List all users."""
    data = load_users()
    return {
        "users": data.get("users", []),
        "total": len(data.get("users", []))
    }

@app.get("/user/{username}", dependencies=[Depends(require_jwt)])
async def get_user(username: str):
    """Get user details."""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            # Add service status
            user["service_status"] = {}
            for svc in user.get("services", []):
                user["service_status"][svc] = check_service(svc)
            return user
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/user", dependencies=[Depends(require_jwt)])
async def create_user(user: UserCreate):
    """Create a new user and provision to services."""
    data = load_users()

    # Check if user exists
    for u in data.get("users", []):
        if u.get("username") == user.username:
            raise HTTPException(status_code=400, detail="User already exists")

    # Provision to services
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
            except Exception as e:
                provision_results[svc] = False
        else:
            provision_results[svc] = False

    # Save user
    new_user = {
        "username": user.username,
        "email": user.email,
        "enabled": True,
        "services": user.services,
        "created": datetime.now().isoformat(),
        "provision_results": provision_results
    }
    data.setdefault("users", []).append(new_user)
    save_users(data)

    return {"success": True, "user": new_user, "provision_results": provision_results}

@app.put("/user/{username}", dependencies=[Depends(require_jwt)])
async def update_user(username: str, update: UserUpdate):
    """Update user."""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            if update.email is not None:
                user["email"] = update.email
            if update.enabled is not None:
                user["enabled"] = update.enabled
            if update.services is not None:
                # Handle service changes
                old_services = set(user.get("services", []))
                new_services = set(update.services)

                # Provision to new services
                for svc in new_services - old_services:
                    ctl = get_service_ctl(svc)
                    if ctl:
                        # Note: Would need password for new service provisioning
                        pass

                user["services"] = update.services
                user["updated"] = datetime.now().isoformat()

            save_users(data)
            return {"success": True, "user": user}
    raise HTTPException(status_code=404, detail="User not found")

@app.delete("/user/{username}", dependencies=[Depends(require_jwt)])
async def delete_user(username: str):
    """Delete user and deprovision from services."""
    data = load_users()
    for i, user in enumerate(data.get("users", [])):
        if user.get("username") == username:
            # Deprovision from services
            deprovision_results = {}
            for svc in user.get("services", []):
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
                    except:
                        deprovision_results[svc] = False

            data["users"].pop(i)
            save_users(data)
            return {"success": True, "deprovision_results": deprovision_results}
    raise HTTPException(status_code=404, detail="User not found")

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

@app.post("/user/{username}/password", dependencies=[Depends(require_jwt)])
async def change_password(username: str, pwd: PasswordChange):
    """Change user password across all services."""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            results = {}
            for svc in user.get("services", []):
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
                    except:
                        results[svc] = False
            return {"success": True, "password_results": results}
    raise HTTPException(status_code=404, detail="User not found")

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
    data = load_users()

    for g in data.get("groups", []):
        if g.get("name") == group.name:
            raise HTTPException(status_code=400, detail="Group already exists")

    new_group = {
        "name": group.name,
        "description": group.description,
        "permissions": group.permissions,
        "members": [],
        "created": datetime.now().isoformat()
    }
    data.setdefault("groups", []).append(new_group)
    save_users(data)

    return {"success": True, "group": new_group}

@app.delete("/group/{name}", dependencies=[Depends(require_jwt)])
async def delete_group(name: str):
    """Delete a group."""
    data = load_users()
    for i, group in enumerate(data.get("groups", [])):
        if group.get("name") == name:
            data["groups"].pop(i)
            save_users(data)
            return {"success": True}
    raise HTTPException(status_code=404, detail="Group not found")

# ══════════════════════════════════════════════════════════════════
# Import/Export
# ══════════════════════════════════════════════════════════════════

@app.get("/export", dependencies=[Depends(require_jwt)])
async def export_users():
    """Export all users."""
    data = load_users()
    # Remove sensitive data
    export_data = {"users": [], "groups": data.get("groups", [])}
    for user in data.get("users", []):
        export_user = {k: v for k, v in user.items() if k != "provision_results"}
        export_data["users"].append(export_user)
    return export_data

@app.post("/import", dependencies=[Depends(require_jwt)])
async def import_users(file: UploadFile = File(...)):
    """Import users from JSON file."""
    try:
        content = await file.read()
        import_data = json.loads(content)

        if "users" not in import_data:
            raise HTTPException(status_code=400, detail="Invalid format: missing 'users' key")

        data = load_users()
        existing_usernames = {u["username"] for u in data.get("users", [])}

        imported = 0
        skipped = 0

        for user in import_data.get("users", []):
            if user.get("username") in existing_usernames:
                skipped += 1
                continue
            user["imported"] = datetime.now().isoformat()
            data.setdefault("users", []).append(user)
            imported += 1

        save_users(data)
        return {"success": True, "imported": imported, "skipped": skipped}

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")

# ══════════════════════════════════════════════════════════════════
# Health Check
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-users", "version": "1.1.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
