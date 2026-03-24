#!/usr/bin/env python3
"""
SecuBox Users API v1.2.0 — Unified Identity Management with RBAC
Roles, Permissions, and Access Control Lists
"""
import subprocess
import json
import os
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, field_validator
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

app = FastAPI(
    title="SecuBox Users API",
    description="Unified Identity Management with RBAC",
    version="1.2.0",
    docs_url="/docs",
    redoc_url=None
)

config = get_config("users") if callable(get_config) else {}
USERSCTL = "/usr/sbin/usersctl"
USERS_FILE = os.environ.get("USERS_FILE", "/etc/secubox/users.json")
ROLES_FILE = os.environ.get("ROLES_FILE", "/etc/secubox/roles.json")
SERVICES = ["nextcloud", "gitea", "email", "matrix", "jellyfin", "peertube", "jabber"]

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

    @field_validator('username')
    @classmethod
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
    data = load_users()
    roles = load_roles()
    valid_role_ids = {r["id"] for r in roles}

    # Validate role IDs
    invalid_roles = [r for r in assignment.roles if r not in valid_role_ids]
    if invalid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid roles: {invalid_roles}")

    for user in data.get("users", []):
        if user.get("username") == username:
            user["roles"] = assignment.roles
            user["roles_updated"] = datetime.now().isoformat()
            save_users(data)
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
    return {"status": "ok", "service": "secubox-users", "version": "1.2.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
