"""SecuBox Users API - Unified Identity Management"""
import subprocess
import json
import os
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Users")
config = get_config("users")

USERS_FILE = config.get("users_file", "/etc/secubox/users.json")
SERVICES = ["nextcloud", "matrix", "gitea", "email", "jellyfin", "peertube", "jabber"]


def load_users() -> dict:
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"users": []}


def save_users(data: dict):
    """Save users to JSON file"""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def check_service(name: str) -> bool:
    """Check if a service is running"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", f"secubox-{name}"],
            capture_output=True, text=True
        )
        return result.stdout.strip() == "active"
    except:
        return False


def provision_user(username: str, email: str, password: str, services: List[str]) -> dict:
    """Provision user to selected services"""
    results = {}
    for svc in services:
        if svc not in SERVICES:
            continue
        ctl = f"/usr/sbin/{svc}ctl"
        if os.path.exists(ctl):
            try:
                result = subprocess.run(
                    [ctl, "user-add", username, email, password],
                    capture_output=True, text=True, timeout=30
                )
                results[svc] = result.returncode == 0
            except:
                results[svc] = False
        else:
            results[svc] = False
    return results


def deprovision_user(username: str, services: List[str]) -> dict:
    """Remove user from services"""
    results = {}
    for svc in services:
        if svc not in SERVICES:
            continue
        ctl = f"/usr/sbin/{svc}ctl"
        if os.path.exists(ctl):
            try:
                result = subprocess.run(
                    [ctl, "user-del", username],
                    capture_output=True, text=True, timeout=30
                )
                results[svc] = result.returncode == 0
            except:
                results[svc] = False
    return results


# Models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    services: List[str] = []

class UserUpdate(BaseModel):
    email: Optional[str] = None
    enabled: Optional[bool] = None
    services: Optional[List[str]] = None


# Public endpoints
@app.get("/status")
async def status():
    """Get users system status"""
    data = load_users()
    user_count = len(data.get("users", []))

    service_status = {}
    for svc in SERVICES:
        service_status[svc] = check_service(svc)

    return {
        "user_count": user_count,
        "domain": config.get("domain", "secubox.local"),
        "services": service_status
    }


@app.get("/services")
async def list_services():
    """List available services and their status"""
    service_status = {}
    for svc in SERVICES:
        service_status[svc] = {
            "running": check_service(svc),
            "ctl_available": os.path.exists(f"/usr/sbin/{svc}ctl")
        }
    return {"services": service_status}


# Protected endpoints
@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List all users"""
    data = load_users()
    return data


@app.get("/user/{username}", dependencies=[Depends(require_jwt)])
async def get_user(username: str):
    """Get user details"""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            return user
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/user", dependencies=[Depends(require_jwt)])
async def create_user(user: UserCreate):
    """Create a new user and provision to services"""
    data = load_users()

    # Check if user exists
    for u in data.get("users", []):
        if u.get("username") == user.username:
            raise HTTPException(status_code=400, detail="User already exists")

    # Provision to services
    results = provision_user(user.username, user.email, user.password, user.services)

    # Save user
    import datetime
    new_user = {
        "username": user.username,
        "email": user.email,
        "enabled": True,
        "services": user.services,
        "created": datetime.datetime.now().isoformat(),
        "provision_results": results
    }
    data.setdefault("users", []).append(new_user)
    save_users(data)

    return {"success": True, "user": new_user, "provision_results": results}


@app.put("/user/{username}", dependencies=[Depends(require_jwt)])
async def update_user(username: str, update: UserUpdate):
    """Update user"""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            if update.email is not None:
                user["email"] = update.email
            if update.enabled is not None:
                user["enabled"] = update.enabled
            if update.services is not None:
                user["services"] = update.services
            save_users(data)
            return {"success": True, "user": user}
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/user/{username}", dependencies=[Depends(require_jwt)])
async def delete_user(username: str):
    """Delete user and deprovision from services"""
    data = load_users()
    for i, user in enumerate(data.get("users", [])):
        if user.get("username") == username:
            # Deprovision from services
            results = deprovision_user(username, user.get("services", []))
            data["users"].pop(i)
            save_users(data)
            return {"success": True, "deprovision_results": results}
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/user/{username}/sync", dependencies=[Depends(require_jwt)])
async def sync_user(username: str):
    """Sync user to all their services"""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            results = {}
            for svc in user.get("services", []):
                ctl = f"/usr/sbin/{svc}ctl"
                if os.path.exists(ctl):
                    try:
                        result = subprocess.run(
                            [ctl, "user-sync", username],
                            capture_output=True, text=True, timeout=30
                        )
                        results[svc] = result.returncode == 0
                    except:
                        results[svc] = False
            return {"success": True, "sync_results": results}
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/user/{username}/password", dependencies=[Depends(require_jwt)])
async def change_password(username: str, password: str):
    """Change user password across all services"""
    data = load_users()
    for user in data.get("users", []):
        if user.get("username") == username:
            results = {}
            for svc in user.get("services", []):
                ctl = f"/usr/sbin/{svc}ctl"
                if os.path.exists(ctl):
                    try:
                        result = subprocess.run(
                            [ctl, "user-passwd", username, password],
                            capture_output=True, text=True, timeout=30
                        )
                        results[svc] = result.returncode == 0
                    except:
                        results[svc] = False
            return {"success": True, "password_results": results}
    raise HTTPException(status_code=404, detail="User not found")
