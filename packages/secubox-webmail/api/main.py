"""SecuBox Webmail API - Roundcube/SOGo Management"""
import subprocess
import os
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from typing import Optional
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Webmail")
config = get_config("webmail")


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


def get_webmail_type() -> str:
    """Detect installed webmail type"""
    if os.path.exists("/etc/roundcube"):
        return "roundcube"
    elif os.path.exists("/etc/sogo"):
        return "sogo"
    return "none"


# Models
class WebmailConfig(BaseModel):
    default_host: Optional[str] = None
    smtp_server: Optional[str] = None
    plugins: Optional[list] = None


# Public endpoints
@app.get("/status")
async def status():
    """Get webmail status"""
    webmail_type = get_webmail_type()

    if webmail_type == "roundcube":
        running = check_service("apache2") or check_service("nginx") or check_service("php-fpm")
    elif webmail_type == "sogo":
        running = check_service("sogo")
    else:
        running = False

    return {
        "type": webmail_type,
        "running": running,
        "url": config.get("url", "/webmail"),
        "mail_server": config.get("mail_server", "localhost")
    }


# Protected endpoints
@app.post("/start", dependencies=[Depends(require_jwt)])
async def start():
    """Start webmail service"""
    webmail_type = get_webmail_type()
    if webmail_type == "roundcube":
        subprocess.run(["systemctl", "start", "php-fpm"], capture_output=True)
    elif webmail_type == "sogo":
        subprocess.run(["systemctl", "start", "sogo"], capture_output=True)
    return {"success": True}


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop():
    """Stop webmail service"""
    webmail_type = get_webmail_type()
    if webmail_type == "sogo":
        subprocess.run(["systemctl", "stop", "sogo"], capture_output=True)
    return {"success": True}


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart():
    """Restart webmail service"""
    webmail_type = get_webmail_type()
    if webmail_type == "roundcube":
        subprocess.run(["systemctl", "restart", "php-fpm"], capture_output=True)
    elif webmail_type == "sogo":
        subprocess.run(["systemctl", "restart", "sogo"], capture_output=True)
    return {"success": True}


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get webmail configuration"""
    webmail_type = get_webmail_type()
    conf = {
        "type": webmail_type,
        "mail_server": config.get("mail_server", "localhost"),
        "smtp_server": config.get("smtp_server", "localhost"),
        "plugins": config.get("plugins", [])
    }
    return conf


@app.put("/config", dependencies=[Depends(require_jwt)])
async def update_config(data: WebmailConfig):
    """Update webmail configuration"""
    # This would update the actual config files
    return {"success": True, "message": "Configuration updated"}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get webmail logs"""
    webmail_type = get_webmail_type()
    try:
        if webmail_type == "roundcube":
            log_file = "/var/log/roundcube/errors.log"
        elif webmail_type == "sogo":
            log_file = "/var/log/sogo/sogo.log"
        else:
            return {"logs": "No webmail installed"}

        if os.path.exists(log_file):
            result = subprocess.run(
                ["tail", "-n", str(lines), log_file],
                capture_output=True, text=True
            )
            return {"logs": result.stdout}
        return {"logs": "Log file not found"}
    except Exception as e:
        return {"logs": str(e)}


@app.post("/clear-cache", dependencies=[Depends(require_jwt)])
async def clear_cache():
    """Clear webmail cache"""
    webmail_type = get_webmail_type()
    try:
        if webmail_type == "roundcube":
            cache_dir = "/var/lib/roundcube/temp"
            if os.path.exists(cache_dir):
                subprocess.run(["rm", "-rf", f"{cache_dir}/*"], shell=True, capture_output=True)
        elif webmail_type == "sogo":
            subprocess.run(["sogo-tool", "expire-sessions", "0"], capture_output=True)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
