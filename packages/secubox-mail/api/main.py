"""SecuBox Mail Server API - Postfix/Dovecot Management"""
import subprocess
import json
import os
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Mail Server")
config = get_config("mail")

MAILCTL = "/usr/sbin/mailctl"
DATA_PATH = config.get("data_path", "/srv/mailserver")


def run_cmd(args: list) -> tuple:
    """Run mailctl command"""
    try:
        result = subprocess.run(
            [MAILCTL] + args,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 1, "", "mailctl not installed"
    except Exception as e:
        return 1, "", str(e)


def check_service(name: str) -> bool:
    """Check if systemd service is running"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True
        )
        return result.stdout.strip() == "active"
    except:
        return False


# Models
class UserCreate(BaseModel):
    email: str
    password: str

class UserPassword(BaseModel):
    email: str
    password: str

class AliasCreate(BaseModel):
    alias: str
    target: str


# Public endpoints
@app.get("/status")
async def status():
    """Get mail server status"""
    postfix_running = check_service("postfix")
    dovecot_running = check_service("dovecot")

    # Count users
    user_count = 0
    users_file = os.path.join(DATA_PATH, "config/users")
    if os.path.exists(users_file):
        with open(users_file) as f:
            user_count = len([l for l in f if l.strip()])

    # Storage usage
    storage = "0"
    try:
        result = subprocess.run(
            ["du", "-sh", DATA_PATH],
            capture_output=True, text=True
        )
        storage = result.stdout.split()[0] if result.stdout else "0"
    except:
        pass

    domain = config.get("domain", "localhost")

    return {
        "postfix_running": postfix_running,
        "dovecot_running": dovecot_running,
        "running": postfix_running and dovecot_running,
        "domain": domain,
        "users": user_count,
        "storage": storage,
        "ssl_valid": os.path.exists(os.path.join(DATA_PATH, "ssl/fullchain.pem"))
    }


@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List mail users"""
    code, out, err = run_cmd(["user-list-json"])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass

    # Fallback: read users file directly
    users = []
    users_file = os.path.join(DATA_PATH, "config/users")
    if os.path.exists(users_file):
        with open(users_file) as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split(":")
                    users.append({"email": parts[0], "quota": parts[1] if len(parts) > 1 else "1G"})
    return {"users": users}


@app.get("/aliases", dependencies=[Depends(require_jwt)])
async def list_aliases():
    """List mail aliases"""
    code, out, err = run_cmd(["alias-list-json"])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass

    aliases = []
    aliases_file = os.path.join(DATA_PATH, "config/aliases")
    if os.path.exists(aliases_file):
        with open(aliases_file) as f:
            for line in f:
                if line.strip() and ":" in line:
                    alias, target = line.strip().split(":", 1)
                    aliases.append({"alias": alias.strip(), "target": target.strip()})
    return {"aliases": aliases}


# Protected endpoints
@app.post("/user", dependencies=[Depends(require_jwt)])
async def add_user(data: UserCreate):
    """Add mail user"""
    code, out, err = run_cmd(["user-add", data.email, data.password])
    return {"success": code == 0, "output": out or err}


@app.delete("/user/{email}", dependencies=[Depends(require_jwt)])
async def delete_user(email: str):
    """Delete mail user"""
    code, out, err = run_cmd(["user-del", email])
    return {"success": code == 0, "output": out or err}


@app.post("/user/password", dependencies=[Depends(require_jwt)])
async def change_password(data: UserPassword):
    """Change user password"""
    code, out, err = run_cmd(["user-passwd", data.email, data.password])
    return {"success": code == 0, "output": out or err}


@app.post("/alias", dependencies=[Depends(require_jwt)])
async def add_alias(data: AliasCreate):
    """Add mail alias"""
    code, out, err = run_cmd(["alias-add", data.alias, data.target])
    return {"success": code == 0, "output": out or err}


@app.delete("/alias/{alias}", dependencies=[Depends(require_jwt)])
async def delete_alias(alias: str):
    """Delete mail alias"""
    code, out, err = run_cmd(["alias-del", alias])
    return {"success": code == 0, "output": out or err}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_services():
    """Start mail services"""
    subprocess.run(["systemctl", "start", "postfix"], capture_output=True)
    subprocess.run(["systemctl", "start", "dovecot"], capture_output=True)
    return {"success": True}


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_services():
    """Stop mail services"""
    subprocess.run(["systemctl", "stop", "postfix"], capture_output=True)
    subprocess.run(["systemctl", "stop", "dovecot"], capture_output=True)
    return {"success": True}


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_services():
    """Restart mail services"""
    subprocess.run(["systemctl", "restart", "postfix"], capture_output=True)
    subprocess.run(["systemctl", "restart", "dovecot"], capture_output=True)
    return {"success": True}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get mail logs"""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "postfix", "-u", "dovecot", "-n", str(lines), "--no-pager"],
            capture_output=True, text=True
        )
        return {"logs": result.stdout}
    except:
        return {"logs": ""}


@app.post("/dns-setup", dependencies=[Depends(require_jwt)])
async def setup_dns():
    """Setup DNS records for mail"""
    code, out, err = run_cmd(["dns-setup"])
    return {"success": code == 0, "output": out or err}


@app.post("/ssl-setup", dependencies=[Depends(require_jwt)])
async def setup_ssl():
    """Setup SSL certificates"""
    code, out, err = run_cmd(["ssl-setup"])
    return {"success": code == 0, "output": out or err}
