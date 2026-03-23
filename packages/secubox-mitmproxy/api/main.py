"""
SecuBox MITMProxy WAF API
HTTP/HTTPS traffic inspection and web application firewall
"""

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import subprocess
import os
import json

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox MITMProxy WAF API", version="1.0.0")

# Configuration
LXC_PATH = Path("/srv/lxc")
LXC_NAME = "mitmproxy"
WAF_DATA_PATH = Path("/srv/mitmproxy-in")
CONFIG_FILE = Path("/etc/secubox/mitmproxy.json")
STATS_CACHE = Path("/tmp/secubox/waf-stats.json")
BANS_CACHE = Path("/tmp/secubox/waf-bans.json")

DEFAULT_CONFIG = {
    "enabled": False,
    "mode": "regular",
    "proxy_port": 8888,
    "web_port": 8081,
    "web_host": "0.0.0.0",
    "data_path": "/srv/mitmproxy",
    "memory_limit": "256M",
    "wan_protection": {
        "enabled": False,
        "wan_interface": "wan",
        "crowdsec_feed": True,
        "block_bots": False
    },
    "transparent": {
        "enabled": False,
        "interface": "br-lan",
        "redirect_http": True,
        "redirect_https": True
    },
    "autoban": {
        "enabled": False,
        "sensitivity": "moderate",
        "ban_duration": "4h"
    }
}


# Models
class SetModeRequest(BaseModel):
    mode: str
    apply_now: bool = False


class SettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = None
    proxy_port: Optional[int] = None
    web_port: Optional[int] = None
    web_host: Optional[str] = None
    data_path: Optional[str] = None
    memory_limit: Optional[str] = None
    wan_protection_enabled: Optional[bool] = None
    wan_interface: Optional[str] = None
    crowdsec_feed: Optional[bool] = None
    block_bots: Optional[bool] = None
    transparent_enabled: Optional[bool] = None
    transparent_interface: Optional[str] = None
    redirect_http: Optional[bool] = None
    redirect_https: Optional[bool] = None
    apply_now: bool = False


class UnbanRequest(BaseModel):
    ip: str


class ToggleWafCategoryRequest(BaseModel):
    category: str
    enabled: bool


# Helpers
def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    """Load mitmproxy configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save mitmproxy configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def lxc_running(name: str = LXC_NAME) -> bool:
    """Check if LXC container is running"""
    success, out, _ = run_cmd(["lxc-info", "-P", str(LXC_PATH), "-n", name, "-s"])
    return success and "RUNNING" in out


def lxc_installed() -> bool:
    """Check if mitmproxy LXC is installed"""
    rootfs = LXC_PATH / LXC_NAME / "rootfs"
    return rootfs.exists() and (rootfs / "usr/bin/mitmproxy").exists()


def nft_table_exists(table: str) -> bool:
    """Check if nftables table exists"""
    success, _, _ = run_cmd(["nft", "list", "table", "inet", table])
    return success


def get_threats_today() -> int:
    """Count threats from today"""
    threats_log = WAF_DATA_PATH / "threats.log"
    if not threats_log.exists():
        return 0

    from datetime import date
    today = date.today().isoformat()
    count = 0

    try:
        with open(threats_log) as f:
            for line in f:
                if today in line:
                    count += 1
    except:
        pass

    return count


def get_autoban_stats() -> dict:
    """Get autoban statistics"""
    from datetime import date
    today = date.today().isoformat()

    autoban_log = WAF_DATA_PATH / "autoban-processed.log"
    pending_log = WAF_DATA_PATH / "autoban-requests.log"

    total = 0
    today_count = 0
    pending = 0

    if autoban_log.exists():
        try:
            with open(autoban_log) as f:
                for line in f:
                    total += 1
                    if line.startswith(today):
                        today_count += 1
        except:
            pass

    if pending_log.exists():
        try:
            pending = sum(1 for _ in open(pending_log))
        except:
            pass

    return {
        "total": total,
        "today": today_count,
        "pending": pending
    }


# Public endpoints
@app.get("/status")
async def get_status():
    """Get mitmproxy WAF status"""
    config = load_config()

    # Check LXC status
    running = False
    for name in ["mitmproxy-in", "mitmproxy-out", LXC_NAME]:
        if lxc_running(name):
            running = True
            break

    installed = lxc_installed()

    # Check nftables
    nft_active = nft_table_exists("mitmproxy")
    nft_wan_active = nft_table_exists("mitmproxy_wan")

    # Get threat stats
    threats_today = get_threats_today()
    autoban_stats = get_autoban_stats()

    # Get token if exists
    token = ""
    token_file = Path(config.get("data_path", "/srv/mitmproxy")) / ".mitmproxy_token"
    if token_file.exists():
        try:
            token = token_file.read_text().strip()
        except:
            pass

    return {
        "enabled": config.get("enabled", False),
        "running": running,
        "installed": installed,
        "lxc_available": True,
        "web_port": config.get("web_port", 8081),
        "proxy_port": config.get("proxy_port", 8888),
        "data_path": config.get("data_path", "/srv/mitmproxy"),
        "mode": config.get("mode", "regular"),
        "nft_active": nft_active,
        "nft_wan_active": nft_wan_active,
        "token": token,
        "wan_protection_enabled": config.get("wan_protection", {}).get("enabled", False),
        "wan_interface": config.get("wan_protection", {}).get("wan_interface", "wan"),
        "crowdsec_feed": config.get("wan_protection", {}).get("crowdsec_feed", True),
        "block_bots": config.get("wan_protection", {}).get("block_bots", False),
        "autoban_enabled": config.get("autoban", {}).get("enabled", False),
        "autoban_sensitivity": config.get("autoban", {}).get("sensitivity", "moderate"),
        "autoban_duration": config.get("autoban", {}).get("ban_duration", "4h"),
        "threats_today": threats_today,
        "autobans_today": autoban_stats["today"],
        "autobans_total": autoban_stats["total"],
        "autobans_pending": autoban_stats["pending"]
    }


@app.get("/status_cached")
async def get_status_cached():
    """Get cached status for fast responses"""
    if STATS_CACHE.exists():
        try:
            return json.loads(STATS_CACHE.read_text())
        except:
            pass

    return {
        "running": False,
        "threats_today": 0,
        "autobans_today": 0,
        "autobans_total": 0,
        "autobans_pending": 0,
        "autoban_enabled": False,
        "mode": "regular"
    }


@app.get("/settings")
async def get_settings():
    """Get mitmproxy settings"""
    return load_config()


@app.get("/alerts")
async def get_alerts():
    """Get recent security alerts"""
    alerts = []
    threats_log = WAF_DATA_PATH / "threats.log"

    if threats_log.exists():
        try:
            lines = []
            with open(threats_log) as f:
                for line in f:
                    lines.append(line.strip())
                    if len(lines) > 50:
                        lines.pop(0)

            for line in reversed(lines):
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except:
                        pass
        except:
            pass

    from datetime import datetime
    return {
        "success": True,
        "alerts": alerts,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/threat_stats")
async def get_threat_stats():
    """Get threat statistics"""
    stats_file = Path("/tmp/secubox-mitm-stats.json")

    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
        except:
            stats = {"total": {"requests": 0, "threats": 0, "bots": 0}}
    else:
        stats = {"total": {"requests": 0, "threats": 0, "bots": 0}}

    from datetime import datetime
    return {
        "success": True,
        "stats": stats,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/bans")
async def get_bans():
    """Get current IP bans"""
    if BANS_CACHE.exists():
        try:
            return json.loads(BANS_CACHE.read_text())
        except:
            pass

    return {
        "success": True,
        "total": 0,
        "mitmproxy_autoban": 0,
        "crowdsec": 0,
        "bans": []
    }


@app.get("/waf_rules")
async def get_waf_rules():
    """Get WAF rules configuration"""
    rules_file = Path("/srv/mitmproxy/waf-rules.json")
    if rules_file.exists():
        try:
            return json.loads(rules_file.read_text())
        except:
            pass

    return {"error": "WAF rules file not found"}


# Protected endpoints
@app.post("/save_settings")
async def save_settings(req: SettingsRequest, user: dict = Depends(require_jwt)):
    """Save mitmproxy settings"""
    config = load_config()

    if req.enabled is not None:
        config["enabled"] = req.enabled
    if req.mode is not None:
        config["mode"] = req.mode
    if req.proxy_port is not None:
        config["proxy_port"] = req.proxy_port
    if req.web_port is not None:
        config["web_port"] = req.web_port
    if req.web_host is not None:
        config["web_host"] = req.web_host
    if req.data_path is not None:
        config["data_path"] = req.data_path
    if req.memory_limit is not None:
        config["memory_limit"] = req.memory_limit

    # WAN protection
    if "wan_protection" not in config:
        config["wan_protection"] = {}
    if req.wan_protection_enabled is not None:
        config["wan_protection"]["enabled"] = req.wan_protection_enabled
    if req.wan_interface is not None:
        config["wan_protection"]["wan_interface"] = req.wan_interface
    if req.crowdsec_feed is not None:
        config["wan_protection"]["crowdsec_feed"] = req.crowdsec_feed
    if req.block_bots is not None:
        config["wan_protection"]["block_bots"] = req.block_bots

    # Transparent
    if "transparent" not in config:
        config["transparent"] = {}
    if req.transparent_enabled is not None:
        config["transparent"]["enabled"] = req.transparent_enabled
    if req.transparent_interface is not None:
        config["transparent"]["interface"] = req.transparent_interface
    if req.redirect_http is not None:
        config["transparent"]["redirect_http"] = req.redirect_http
    if req.redirect_https is not None:
        config["transparent"]["redirect_https"] = req.redirect_https

    save_config(config)

    restarted = False
    if req.apply_now and config.get("enabled"):
        run_cmd(["systemctl", "restart", "secubox-mitmproxy"])
        restarted = True

    return {
        "success": True,
        "message": "Settings saved and applied" if restarted else "Settings saved",
        "restarted": restarted
    }


@app.post("/set_mode")
async def set_mode(req: SetModeRequest, user: dict = Depends(require_jwt)):
    """Set mitmproxy mode"""
    valid_modes = ["regular", "transparent", "upstream", "reverse"]
    if req.mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {req.mode}")

    config = load_config()
    config["mode"] = req.mode
    save_config(config)

    restarted = False
    if req.apply_now and config.get("enabled"):
        run_cmd(["systemctl", "restart", "secubox-mitmproxy"])
        restarted = True

    return {
        "success": True,
        "mode": req.mode,
        "message": f"Mode set to {req.mode}" + (" and applied" if restarted else ""),
        "restarted": restarted
    }


@app.post("/start")
async def start(user: dict = Depends(require_jwt)):
    """Start mitmproxy"""
    run_cmd(["systemctl", "start", "secubox-mitmproxy"])
    return {"success": True}


@app.post("/stop")
async def stop(user: dict = Depends(require_jwt)):
    """Stop mitmproxy"""
    run_cmd(["systemctl", "stop", "secubox-mitmproxy"])
    return {"success": True}


@app.post("/restart")
async def restart(user: dict = Depends(require_jwt)):
    """Restart mitmproxy"""
    run_cmd(["systemctl", "restart", "secubox-mitmproxy"])
    return {"success": True}


@app.post("/setup_firewall")
async def setup_firewall(user: dict = Depends(require_jwt)):
    """Setup firewall rules for transparent mode"""
    success, out, err = run_cmd(["mitmproxyctl", "firewall-setup"])
    if success:
        return {"success": True, "message": "Firewall rules applied"}
    return {"success": False, "error": "Failed to setup firewall rules", "details": err}


@app.post("/clear_firewall")
async def clear_firewall(user: dict = Depends(require_jwt)):
    """Clear firewall rules"""
    success, out, err = run_cmd(["mitmproxyctl", "firewall-clear"])
    if success:
        return {"success": True, "message": "Firewall rules cleared"}
    return {"success": False, "error": "Failed to clear firewall rules"}


@app.post("/wan_setup")
async def wan_setup(user: dict = Depends(require_jwt)):
    """Setup WAN protection rules"""
    success, out, err = run_cmd(["mitmproxyctl", "wan-setup"])
    if success:
        return {"success": True, "message": "WAN protection rules applied"}
    return {"success": False, "error": "Failed to setup WAN protection rules", "details": err}


@app.post("/wan_clear")
async def wan_clear(user: dict = Depends(require_jwt)):
    """Clear WAN protection rules"""
    success, out, err = run_cmd(["mitmproxyctl", "wan-clear"])
    if success:
        return {"success": True, "message": "WAN protection rules cleared"}
    return {"success": False, "error": "Failed to clear WAN protection rules"}


@app.post("/clear_alerts")
async def clear_alerts(user: dict = Depends(require_jwt)):
    """Clear security alerts"""
    threats_log = WAF_DATA_PATH / "threats.log"
    try:
        threats_log.write_text("")
        return {"success": True, "message": "Alerts cleared"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/unban")
async def unban(req: UnbanRequest, user: dict = Depends(require_jwt)):
    """Unban an IP address"""
    success, out, err = run_cmd(["cscli", "decisions", "delete", "--ip", req.ip])
    if success:
        return {"success": True, "message": f"Unbanned {req.ip}"}
    return {"success": False, "error": f"Failed to unban {req.ip}"}


@app.post("/toggle_waf_category")
async def toggle_waf_category(req: ToggleWafCategoryRequest, user: dict = Depends(require_jwt)):
    """Toggle WAF category enabled state"""
    rules_file = Path("/srv/mitmproxy/waf-rules.json")
    if not rules_file.exists():
        return {"error": "WAF rules file not found"}

    try:
        rules = json.loads(rules_file.read_text())
        if "categories" in rules and req.category in rules["categories"]:
            rules["categories"][req.category]["enabled"] = req.enabled
            rules_file.write_text(json.dumps(rules, indent=2))
            return {"success": True}
        return {"error": "Category not found"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-mitmproxy",
        "version": "1.0.0",
        "description": "HTTP/HTTPS traffic inspection and web application firewall"
    }
