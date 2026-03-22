"""
secubox-wireguard - FastAPI application
Port de luci-app-wireguard-dashboard vers Debian

Three-fold architecture:
  - /components : what is this module made of
  - /status     : health and runtime state
  - /access     : how to connect
"""
import asyncio
import json
import subprocess
import base64
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

log = get_logger("wireguard")

app = FastAPI(
    title="secubox-wireguard",
    version="1.0.0",
    root_path="/api/v1/wireguard",
)

app.include_router(auth_router, prefix="/auth")


# === Helper: run wgctl ===
async def _run_ctl(*args, timeout: int = 30) -> dict:
    """Run wgctl and return JSON output."""
    cmd = ["/usr/sbin/wgctl"] + list(args)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode().strip()
        if proc.returncode == 0 and output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return {"output": output, "success": True}
        return {"success": proc.returncode == 0, "output": output, "error": stderr.decode().strip()}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        log.error("wgctl error: %s", e)
        return {"success": False, "error": str(e)}


# === Three-Fold Architecture Endpoints ===

@app.get("/components")
async def components():
    """List system components (public, three-fold: what)."""
    return await _run_ctl("components")


@app.get("/status")
async def status():
    """Show health status (public, three-fold: health)."""
    return await _run_ctl("status")


@app.get("/access")
async def access():
    """Show connection endpoints (public, three-fold: how)."""
    return await _run_ctl("access")


# === Interface Management ===

@app.get("/interfaces")
async def list_interfaces():
    """List all WireGuard interfaces (public)."""
    return await _run_ctl("interfaces")


@app.post("/interface/{name}/up")
async def interface_up(name: str, user=Depends(require_jwt)):
    """Bring interface up."""
    log.info("Bringing up interface: %s", name)
    return await _run_ctl("interface", "up", name)


@app.post("/interface/{name}/down")
async def interface_down(name: str, user=Depends(require_jwt)):
    """Bring interface down."""
    log.info("Bringing down interface: %s", name)
    return await _run_ctl("interface", "down", name)


# === Peer Management ===

@app.get("/peers")
async def list_peers(interface: Optional[str] = None):
    """List all peers (public)."""
    if interface:
        return await _run_ctl("peers", interface)
    return await _run_ctl("peers")


class PeerAddRequest(BaseModel):
    name: str
    interface: str = "wg0"


@app.post("/peer")
async def add_peer(req: PeerAddRequest, user=Depends(require_jwt)):
    """Add new peer with auto-generated config."""
    log.info("Adding peer: %s to %s", req.name, req.interface)
    return await _run_ctl("peer", "add", req.name, req.interface)


class PeerRemoveRequest(BaseModel):
    identifier: str
    interface: Optional[str] = None


@app.delete("/peer")
async def remove_peer(req: PeerRemoveRequest, user=Depends(require_jwt)):
    """Remove peer by name or public key."""
    log.info("Removing peer: %s", req.identifier)
    if req.interface:
        return await _run_ctl("peer", "remove", req.identifier, req.interface)
    return await _run_ctl("peer", "remove", req.identifier)


@app.get("/peer/{name}/config")
async def peer_config(name: str, user=Depends(require_jwt)):
    """Get peer config file content."""
    result = await _run_ctl("peer", "config", name)
    if "output" in result:
        return {"config": result["output"]}
    return result


@app.get("/peer/{name}/qr")
async def peer_qr(name: str, user=Depends(require_jwt)):
    """Get peer QR code as base64 PNG."""
    import os
    qr_path = f"/var/lib/secubox/wireguard/peers/{name}.png"
    if os.path.exists(qr_path):
        with open(qr_path, "rb") as f:
            qr_data = base64.b64encode(f.read()).decode()
        return {"qr_base64": qr_data, "name": name}
    return {"error": "QR code not found", "name": name}


# === Key Generation ===

@app.post("/genkey")
async def generate_keypair(user=Depends(require_jwt)):
    """Generate new WireGuard key pair."""
    return await _run_ctl("genkey")


@app.post("/genpsk")
async def generate_psk(user=Depends(require_jwt)):
    """Generate new preshared key."""
    return await _run_ctl("genpsk")


# === Migration ===

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"
    dry_run: bool = False


@app.post("/migrate")
async def migrate(req: MigrateRequest, user=Depends(require_jwt)):
    """Migrate WireGuard configuration from OpenWrt."""
    log.info("Migration requested from %s (dry_run=%s)", req.source, req.dry_run)
    args = ["migrate", req.source]
    if req.dry_run:
        args.append("--dry-run")
    return await _run_ctl(*args, timeout=120)


# === Health Check ===

@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        result = subprocess.run(["wg", "show", "interfaces"], capture_output=True, timeout=2)
        interfaces = result.stdout.decode().strip().split() if result.returncode == 0 else []
        return {
            "status": "ok",
            "module": "wireguard",
            "interfaces": len(interfaces),
        }
    except Exception as e:
        return {"status": "error", "module": "wireguard", "error": str(e)}
