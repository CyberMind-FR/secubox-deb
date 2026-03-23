"""
SecuBox Tor Shield API
Tor anonymity network and hidden services management
"""

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import subprocess
import os
import json
import socket
import httpx
import asyncio

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Tor Shield API", version="1.0.0")

# Configuration
TOR_CONTROL_PORT = 9051
TOR_SOCKS_PORT = 9050
TOR_DATA = Path("/var/lib/tor")
TOR_CONTROL_SOCKET = Path("/run/tor/control")
CONFIG_FILE = Path("/etc/secubox/tor.json")

DEFAULT_CONFIG = {
    "enabled": False,
    "mode": "transparent",
    "dns_over_tor": True,
    "kill_switch": True,
    "bridges_enabled": False,
    "bridge_type": "obfs4",
    "hidden_services": []
}


# Models
class EnableRequest(BaseModel):
    preset: str = "anonymous"


class HiddenService(BaseModel):
    name: str
    local_port: int = 80
    virtual_port: int = 80


class HiddenServiceRemove(BaseModel):
    name: str


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
    """Load Tor configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save Tor configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def tor_running() -> bool:
    """Check if Tor is running"""
    success, out, _ = run_cmd(["pgrep", "-x", "tor"])
    return success and out.strip() != ""


def tor_control(command: str) -> str:
    """Send command to Tor control port"""
    try:
        # Try control socket first
        if TOR_CONTROL_SOCKET.exists():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(str(TOR_CONTROL_SOCKET))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", TOR_CONTROL_PORT))

        # Authenticate (cookie or password)
        cookie_file = Path("/run/tor/control.authcookie")
        if cookie_file.exists():
            cookie = cookie_file.read_bytes().hex()
            sock.send(f"AUTHENTICATE {cookie}\r\n".encode())
        else:
            sock.send(b"AUTHENTICATE\r\n")

        response = sock.recv(1024).decode()
        if "250 OK" not in response:
            sock.close()
            return ""

        # Send actual command
        sock.send(f"{command}\r\n".encode())
        response = sock.recv(4096).decode()
        sock.close()
        return response
    except Exception as e:
        return ""


def get_bootstrap_progress() -> int:
    """Get Tor bootstrap percentage"""
    response = tor_control("GETINFO status/bootstrap-phase")
    if "PROGRESS=" in response:
        try:
            progress = response.split("PROGRESS=")[1].split()[0]
            return int(progress)
        except:
            pass
    return 0


def get_circuit_count() -> int:
    """Get number of built circuits"""
    response = tor_control("GETINFO circuit-status")
    return response.count("BUILT")


def get_traffic_stats() -> tuple:
    """Get bytes read/written"""
    read_resp = tor_control("GETINFO traffic/read")
    write_resp = tor_control("GETINFO traffic/written")

    bytes_read = 0
    bytes_written = 0

    if "250" in read_resp:
        try:
            bytes_read = int(read_resp.split("250")[0].split("=")[1].strip())
        except:
            pass

    if "250" in write_resp:
        try:
            bytes_written = int(write_resp.split("250")[0].split("=")[1].strip())
        except:
            pass

    return bytes_read, bytes_written


# Public endpoints
@app.get("/status")
async def get_status():
    """Get Tor Shield status"""
    config = load_config()
    running = tor_running()

    status = {
        "enabled": config.get("enabled", False),
        "running": running,
        "mode": config.get("mode", "transparent"),
        "dns_over_tor": config.get("dns_over_tor", True),
        "kill_switch": config.get("kill_switch", True),
        "bridges_enabled": config.get("bridges_enabled", False),
        "bridge_type": config.get("bridge_type", "obfs4")
    }

    if running:
        status["bootstrap"] = get_bootstrap_progress()
        status["circuit_count"] = get_circuit_count()
        bytes_read, bytes_written = get_traffic_stats()
        status["bytes_read"] = bytes_read
        status["bytes_written"] = bytes_written

        # Get exit IP from cache
        exit_ip_cache = Path("/tmp/tor_exit_ip")
        if exit_ip_cache.exists():
            status["exit_ip"] = exit_ip_cache.read_text().strip()
            status["is_tor"] = True
        else:
            status["exit_ip"] = "unknown"
            status["is_tor"] = False
    else:
        status["bootstrap"] = 0
        status["circuit_count"] = 0
        status["bytes_read"] = 0
        status["bytes_written"] = 0

    return status


@app.get("/circuits")
async def get_circuits():
    """Get active Tor circuits"""
    if not tor_running():
        return {"circuits": []}

    response = tor_control("GETINFO circuit-status")
    circuits = []

    for line in response.split('\n'):
        if "BUILT" in line:
            parts = line.split()
            if len(parts) >= 3:
                circuit_id = parts[0]
                status = parts[1]
                path = parts[2] if len(parts) > 2 else ""

                # Parse nodes from path
                nodes = []
                for node in path.split(','):
                    if '~' in node:
                        fp, name = node.split('~', 1)
                        nodes.append({"fingerprint": fp.lstrip('$'), "name": name})
                    elif node:
                        nodes.append({"fingerprint": node.lstrip('$'), "name": node})

                circuits.append({
                    "id": circuit_id,
                    "status": status,
                    "path": path,
                    "nodes": nodes
                })

    return {"circuits": circuits}


@app.get("/hidden_services")
async def get_hidden_services():
    """Get configured hidden services"""
    config = load_config()
    services = []

    for hs in config.get("hidden_services", []):
        hostname_file = TOR_DATA / f"hidden_service_{hs['name']}" / "hostname"
        onion_address = ""
        if hostname_file.exists():
            onion_address = hostname_file.read_text().strip()

        services.append({
            "name": hs["name"],
            "enabled": hs.get("enabled", True),
            "local_port": hs.get("local_port", 80),
            "virtual_port": hs.get("virtual_port", 80),
            "onion_address": onion_address
        })

    return {"services": services}


# Protected endpoints
@app.post("/enable")
async def enable_tor(req: EnableRequest, user: dict = Depends(require_jwt)):
    """Enable Tor Shield"""
    config = load_config()

    # Apply preset
    presets = {
        "anonymous": {"mode": "transparent", "dns_over_tor": True, "kill_switch": True},
        "stealth": {"mode": "transparent", "dns_over_tor": True, "kill_switch": True, "bridges_enabled": True},
        "minimal": {"mode": "socks", "dns_over_tor": True, "kill_switch": False}
    }

    preset_config = presets.get(req.preset, presets["anonymous"])
    config.update(preset_config)
    config["enabled"] = True
    config["current_preset"] = req.preset
    save_config(config)

    # Start Tor service
    run_cmd(["systemctl", "start", "tor"])

    return {
        "success": True,
        "message": f"Tor Shield enabling with preset: {req.preset}",
        "preset": req.preset
    }


@app.post("/disable")
async def disable_tor(user: dict = Depends(require_jwt)):
    """Disable Tor Shield"""
    config = load_config()
    config["enabled"] = False
    save_config(config)

    # Stop Tor service
    run_cmd(["systemctl", "stop", "tor"])

    return {"success": True, "message": "Tor Shield disabled"}


@app.post("/new_identity")
async def new_identity(user: dict = Depends(require_jwt)):
    """Request a new Tor identity"""
    if not tor_running():
        raise HTTPException(status_code=400, detail="Tor is not running")

    response = tor_control("SIGNAL NEWNYM")

    if "250 OK" in response:
        # Clear cached exit IP
        exit_ip_cache = Path("/tmp/tor_exit_ip")
        if exit_ip_cache.exists():
            exit_ip_cache.unlink()

        return {"success": True, "message": "New identity requested"}
    else:
        return {"success": False, "error": "Failed to request new identity"}


@app.post("/check_leaks")
async def check_leaks(user: dict = Depends(require_jwt)):
    """Check for IP/DNS leaks"""
    if not tor_running():
        raise HTTPException(status_code=400, detail="Tor is not running")

    tests = []
    leak_count = 0

    # IP leak test
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get real IP
            real_ip_resp = await client.get("https://api.ipify.org")
            real_ip = real_ip_resp.text.strip()

            # Get Tor exit IP
            tor_check = await client.get(
                "https://check.torproject.org/api/ip",
                proxies=f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"
            )
            tor_data = tor_check.json()
            tor_ip = tor_data.get("IP", "")
            is_tor = tor_data.get("IsTor", False)

            # IP leak test
            if tor_ip and tor_ip != real_ip:
                tests.append({"name": "IP Leak", "passed": True, "message": "IP protected"})
            else:
                tests.append({"name": "IP Leak", "passed": False, "message": "Potential IP leak"})
                leak_count += 1

            # Tor detection test
            if is_tor:
                tests.append({"name": "Tor Detection", "passed": True, "message": "Traffic via Tor confirmed"})
            else:
                tests.append({"name": "Tor Detection", "passed": False, "message": "Traffic may not be through Tor"})
                leak_count += 1

    except Exception as e:
        tests.append({"name": "Connection", "passed": False, "message": str(e)})
        leak_count += 1

    return {
        "tests": tests,
        "leak_count": leak_count,
        "protected": leak_count == 0
    }


@app.post("/hidden_service/add")
async def add_hidden_service(req: HiddenService, user: dict = Depends(require_jwt)):
    """Add a hidden service"""
    config = load_config()

    # Sanitize name
    name = "".join(c for c in req.name if c.isalnum() or c in "_-")

    # Check if already exists
    for hs in config.get("hidden_services", []):
        if hs["name"] == name:
            raise HTTPException(status_code=400, detail="Hidden service already exists")

    if "hidden_services" not in config:
        config["hidden_services"] = []

    config["hidden_services"].append({
        "name": name,
        "enabled": True,
        "local_port": req.local_port,
        "virtual_port": req.virtual_port
    })

    save_config(config)

    # Restart Tor to apply
    if config.get("enabled"):
        run_cmd(["systemctl", "reload", "tor"])

    return {"success": True, "message": "Hidden service created", "name": name}


@app.post("/hidden_service/remove")
async def remove_hidden_service(req: HiddenServiceRemove, user: dict = Depends(require_jwt)):
    """Remove a hidden service"""
    config = load_config()

    # Find and remove
    hidden_services = config.get("hidden_services", [])
    config["hidden_services"] = [hs for hs in hidden_services if hs["name"] != req.name]

    save_config(config)

    # Remove data directory
    hs_dir = TOR_DATA / f"hidden_service_{req.name}"
    if hs_dir.exists():
        import shutil
        shutil.rmtree(hs_dir, ignore_errors=True)

    # Restart Tor to apply
    if config.get("enabled"):
        run_cmd(["systemctl", "reload", "tor"])

    return {"success": True, "message": "Hidden service removed"}


@app.post("/refresh_ips")
async def refresh_ips(user: dict = Depends(require_jwt)):
    """Refresh cached IP addresses"""
    # Run in background
    async def fetch_ips():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Real IP
                real_resp = await client.get("https://api.ipify.org")
                Path("/tmp/tor_real_ip").write_text(real_resp.text.strip())

                # Tor exit IP
                if tor_running():
                    tor_resp = await client.get(
                        "https://check.torproject.org/api/ip",
                        proxies=f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"
                    )
                    tor_data = tor_resp.json()
                    Path("/tmp/tor_exit_ip").write_text(tor_data.get("IP", ""))
        except:
            pass

    asyncio.create_task(fetch_ips())

    return {"success": True, "message": "IP refresh started"}


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-tor",
        "version": "1.0.0",
        "description": "Tor anonymity network and hidden services"
    }
