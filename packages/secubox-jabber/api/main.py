#!/usr/bin/env python3
"""SecuBox Jabber API - XMPP Server with Prosody"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import os
from pathlib import Path

app = FastAPI(title="SecuBox Jabber API", version="1.0.0")

PROSODY_CONFIG = Path("/etc/prosody/prosody.cfg.lua")
PROSODY_HOSTS = Path("/etc/prosody/conf.d")
DATA_DIR = Path("/var/lib/prosody")


class User(BaseModel):
    username: str
    password: str
    domain: str


class VirtualHost(BaseModel):
    domain: str
    enable_registration: Optional[bool] = False


def run_cmd(cmd: list, timeout: int = 30) -> dict:
    """Run command and return result"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def prosodyctl(cmd: str) -> dict:
    """Run prosodyctl command"""
    return run_cmd(["prosodyctl"] + cmd.split())


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "jabber"}


@app.get("/status")
async def status():
    """Get Prosody status"""
    result = run_cmd(["systemctl", "is-active", "prosody"])
    running = result.get("stdout", "").strip() == "active"
    installed = Path("/usr/bin/prosodyctl").exists()

    stats = {"users": 0, "hosts": []}
    if running and installed:
        # Get hosts
        result = prosodyctl("about")
        if result["success"]:
            for line in result["stdout"].split("\n"):
                if "VirtualHost" in line:
                    host = line.split('"')[1] if '"' in line else ""
                    if host:
                        stats["hosts"].append(host)

        # Count users per host
        for host in stats["hosts"]:
            result = run_cmd(["ls", f"/var/lib/prosody/{host.replace('.', '%2e')}/accounts/"])
            if result["success"]:
                stats["users"] += len(result["stdout"].strip().split("\n")) if result["stdout"].strip() else 0

    return {
        "installed": installed,
        "running": running,
        "users": stats["users"],
        "hosts": stats["hosts"],
        "c2s_port": 5222,
        "s2s_port": 5269
    }


@app.post("/install")
async def install(domain: str = "localhost"):
    """Install Prosody XMPP server"""
    result = run_cmd(["apt-get", "install", "-y", "prosody", "lua-sec"], timeout=180)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Install failed: {result.get('stderr')}")

    # Create hosts directory
    PROSODY_HOSTS.mkdir(parents=True, exist_ok=True)

    # Create initial host config
    host_config = f'''VirtualHost "{domain}"
    enabled = true
    allow_registration = false

    ssl = {{
        key = "/etc/prosody/certs/{domain}.key";
        certificate = "/etc/prosody/certs/{domain}.crt";
    }}
'''
    host_file = PROSODY_HOSTS / f"{domain}.cfg.lua"
    with open(host_file, "w") as f:
        f.write(host_config)

    # Generate self-signed cert
    run_cmd(["prosodyctl", "cert", "generate", domain])

    # Enable and start
    run_cmd(["systemctl", "enable", "prosody"])
    run_cmd(["systemctl", "start", "prosody"])

    return {"success": True, "message": f"Prosody installed with domain {domain}"}


@app.post("/start")
async def start():
    """Start Prosody"""
    result = run_cmd(["systemctl", "start", "prosody"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))
    return {"success": True}


@app.post("/stop")
async def stop():
    """Stop Prosody"""
    result = run_cmd(["systemctl", "stop", "prosody"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))
    return {"success": True}


@app.post("/restart")
async def restart():
    """Restart Prosody"""
    result = run_cmd(["systemctl", "restart", "prosody"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Restart failed"))
    return {"success": True}


@app.post("/reload")
async def reload():
    """Reload Prosody configuration"""
    result = prosodyctl("reload")
    if not result["success"]:
        raise HTTPException(status_code=500, detail="Reload failed")
    return {"success": True}


@app.get("/users")
async def list_users(domain: Optional[str] = None):
    """List XMPP users"""
    users = []

    if DATA_DIR.exists():
        for host_dir in DATA_DIR.iterdir():
            if host_dir.is_dir():
                host = host_dir.name.replace("%2e", ".")
                if domain and host != domain:
                    continue
                accounts_dir = host_dir / "accounts"
                if accounts_dir.exists():
                    for account in accounts_dir.iterdir():
                        if account.suffix == ".dat":
                            users.append({
                                "username": account.stem,
                                "domain": host,
                                "jid": f"{account.stem}@{host}"
                            })

    return {"users": users}


@app.post("/users")
async def create_user(user: User):
    """Create a new XMPP user"""
    result = run_cmd(["prosodyctl", "adduser", f"{user.username}@{user.domain}"],
                     timeout=10)

    # prosodyctl adduser is interactive, use register instead
    result = run_cmd(["prosodyctl", "register", user.username, user.domain, user.password])

    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {result.get('stderr')}")

    return {"success": True, "jid": f"{user.username}@{user.domain}"}


@app.delete("/users/{jid}")
async def delete_user(jid: str):
    """Delete an XMPP user"""
    result = prosodyctl(f"deluser {jid}")
    if not result["success"]:
        raise HTTPException(status_code=500, detail="Failed to delete user")
    return {"success": True}


@app.post("/users/{jid}/password")
async def change_password(jid: str, password: str):
    """Change user password"""
    username, domain = jid.split("@")
    result = run_cmd(["prosodyctl", "register", username, domain, password])
    if not result["success"]:
        raise HTTPException(status_code=500, detail="Failed to change password")
    return {"success": True}


@app.get("/hosts")
async def list_hosts():
    """List virtual hosts"""
    hosts = []

    if PROSODY_HOSTS.exists():
        for cfg in PROSODY_HOSTS.glob("*.cfg.lua"):
            domain = cfg.stem
            with open(cfg) as f:
                content = f.read()

            hosts.append({
                "domain": domain,
                "enabled": "enabled = true" in content,
                "registration": "allow_registration = true" in content
            })

    return {"hosts": hosts}


@app.post("/hosts")
async def create_host(host: VirtualHost):
    """Create a new virtual host"""
    PROSODY_HOSTS.mkdir(parents=True, exist_ok=True)

    host_file = PROSODY_HOSTS / f"{host.domain}.cfg.lua"
    if host_file.exists():
        raise HTTPException(status_code=400, detail="Host already exists")

    config = f'''VirtualHost "{host.domain}"
    enabled = true
    allow_registration = {"true" if host.enable_registration else "false"}
'''

    with open(host_file, "w") as f:
        f.write(config)

    # Generate certificate
    run_cmd(["prosodyctl", "cert", "generate", host.domain])

    # Reload
    prosodyctl("reload")

    return {"success": True, "domain": host.domain}


@app.delete("/hosts/{domain}")
async def delete_host(domain: str):
    """Delete a virtual host"""
    host_file = PROSODY_HOSTS / f"{domain}.cfg.lua"
    if host_file.exists():
        host_file.unlink()
        prosodyctl("reload")
        return {"success": True}
    raise HTTPException(status_code=404, detail="Host not found")


@app.get("/logs")
async def get_logs(lines: int = 100):
    """Get Prosody logs"""
    log_file = Path("/var/log/prosody/prosody.log")
    if not log_file.exists():
        return {"logs": []}

    result = run_cmd(["tail", "-n", str(lines), str(log_file)])
    if result["success"]:
        return {"logs": result["stdout"].split("\n")}
    return {"logs": []}


@app.get("/online")
async def online_users():
    """Get currently online users"""
    result = prosodyctl("c2s:show()")
    if not result["success"]:
        return {"online": []}

    online = []
    for line in result["stdout"].split("\n"):
        if "@" in line and "(" in line:
            jid = line.split()[0]
            online.append(jid)

    return {"online": online}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
