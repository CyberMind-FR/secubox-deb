"""secubox-homeassistant -- FastAPI application for Home Assistant Integration.

SecuBox-DEB Home automation hub module.
Provides Home Assistant container/LXC management, entity control, and automation management.
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import httpx

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-homeassistant", version="1.0.0", root_path="/api/v1/homeassistant")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("homeassistant")

# Configuration
CONFIG_FILE = Path("/etc/secubox/homeassistant.toml")
DATA_PATH = Path("/srv/homeassistant")
CACHE_FILE = Path("/var/cache/secubox/homeassistant/stats.json")
LXC_NAME = "homeassistant"
DEFAULT_PORT = 8123

DEFAULT_CONFIG = {
    "ha_url": "http://127.0.0.1:8123",
    "token": "",
    "container_name": "homeassistant",
    "container_type": "docker",  # docker, podman, or lxc
    "image": "ghcr.io/home-assistant/home-assistant:stable",
    "port": 8123,
    "timezone": "UTC",
}

_cache: dict = {}


# ============================================================================
# Models
# ============================================================================

class HomeAssistantConfig(BaseModel):
    ha_url: str = "http://127.0.0.1:8123"
    token: Optional[str] = ""
    container_name: str = "homeassistant"
    container_type: str = "docker"
    image: str = "ghcr.io/home-assistant/home-assistant:stable"
    port: int = 8123
    timezone: str = "UTC"


class EntityCommand(BaseModel):
    domain: str
    service: str
    data: Optional[Dict[str, Any]] = None


class IntegrationInstall(BaseModel):
    integration: str
    config: Optional[Dict[str, Any]] = None


class AutomationToggle(BaseModel):
    automation_id: str
    enabled: bool


class AddonInstall(BaseModel):
    addon_slug: str
    version: Optional[str] = None


class BackupCreate(BaseModel):
    name: Optional[str] = None
    include_homeassistant: bool = True
    include_addons: bool = True


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load Home Assistant configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def detect_runtime() -> Optional[str]:
    """Detect container runtime (podman, docker, or lxc)."""
    cfg = get_config()
    preferred = cfg.get("container_type", "docker")

    if preferred == "lxc":
        if shutil.which("lxc-info") or shutil.which("lxc"):
            return "lxc"

    if preferred == "podman" and shutil.which("podman"):
        return "podman"

    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    if shutil.which("lxc-info"):
        return "lxc"

    return None


def lxc_running() -> bool:
    """Check if LXC container is running."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-s"],
            capture_output=True, text=True, timeout=10
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False


def lxc_exists() -> bool:
    """Check if LXC container exists."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def lxc_get_ip() -> Optional[str]:
    """Get LXC container IP address."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-iH"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            ips = result.stdout.strip().split("\n")
            for ip in ips:
                if ip and not ip.startswith("127."):
                    return ip.strip()
        return None
    except Exception:
        return None


def is_running() -> bool:
    """Check if Home Assistant container is running."""
    rt = detect_runtime()
    cfg = get_config()
    container = cfg.get("container_name", "homeassistant")

    if not rt:
        return False

    try:
        if rt == "lxc":
            return lxc_running()
        else:
            result = subprocess.run(
                [rt, "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5
            )
            names = result.stdout.split()
            return container in names
    except Exception:
        return False


def get_ha_headers() -> dict:
    """Get headers for Home Assistant API calls."""
    cfg = get_config()
    token = cfg.get("token", "")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get_ha_url() -> str:
    """Get Home Assistant API URL."""
    cfg = get_config()
    rt = detect_runtime()

    if rt == "lxc":
        ip = lxc_get_ip()
        if ip:
            return f"http://{ip}:{DEFAULT_PORT}"

    return cfg.get("ha_url", "http://127.0.0.1:8123")


async def ha_api_request(endpoint: str, method: str = "GET", json_data: dict = None) -> dict:
    """Make request to Home Assistant API."""
    url = f"{get_ha_url()}/api/{endpoint}"
    headers = get_ha_headers()

    async with httpx.AsyncClient(timeout=30.0) as client:
        if method == "GET":
            resp = await client.get(url, headers=headers)
        else:
            resp = await client.post(url, headers=headers, json=json_data or {})

        if resp.status_code == 401:
            raise HTTPException(401, "Invalid Home Assistant token")

        resp.raise_for_status()

        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return {"status": "ok"}


async def refresh_cache():
    """Background task to refresh status cache."""
    global _cache
    while True:
        try:
            if is_running():
                try:
                    states = await ha_api_request("states")
                    _cache["entity_count"] = len(states) if isinstance(states, list) else 0
                    _cache["last_update"] = datetime.now().isoformat()
                except Exception:
                    pass

            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(_cache))
        except Exception as e:
            log.error(f"Cache refresh failed: {e}")

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_cache())


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "homeassistant"}


@router.get("/status")
async def status():
    """Get Home Assistant service status."""
    cfg = get_config()
    rt = detect_runtime()
    running = is_running()

    uptime = 0
    version = "unknown"
    entity_count = _cache.get("entity_count", 0)
    web_accessible = False
    container_ip = None

    if running:
        container = cfg.get("container_name", "homeassistant")

        # Get IP for LXC
        if rt == "lxc":
            container_ip = lxc_get_ip()

        # Get uptime for Docker/Podman
        if rt and rt != "lxc":
            try:
                result = subprocess.run(
                    [rt, "ps", "--filter", f"name={container}", "--format", "{{.Status}}"],
                    capture_output=True, text=True, timeout=5
                )
                status_str = result.stdout.strip().split('\n')[0] if result.stdout else ""
                if "minute" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 60
                elif "hour" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 3600
                elif "day" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 86400
            except Exception:
                pass

        # Check web accessibility and get version
        try:
            ha_url = get_ha_url()
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{ha_url}/")
                web_accessible = resp.status_code in [200, 401]

            if web_accessible and cfg.get("token"):
                try:
                    config_data = await ha_api_request("config")
                    version = config_data.get("version", "unknown")
                except Exception:
                    pass
        except Exception:
            pass

    return {
        "running": running,
        "uptime": uptime,
        "version": version,
        "ha_url": get_ha_url(),
        "port": cfg.get("port", 8123),
        "container_name": cfg.get("container_name", "homeassistant"),
        "container_type": cfg.get("container_type", "docker"),
        "container_ip": container_ip,
        "runtime": rt or "none",
        "web_accessible": web_accessible,
        "entity_count": entity_count,
        "token_configured": bool(cfg.get("token")),
    }


# ============================================================================
# Protected Endpoints (JWT required)
# ============================================================================

@router.get("/config")
async def get_homeassistant_config(user=Depends(require_jwt)):
    """Get Home Assistant configuration."""
    cfg = get_config()
    cfg_safe = cfg.copy()
    if cfg_safe.get("token"):
        cfg_safe["token"] = "********"
    return cfg_safe


@router.post("/config")
async def set_homeassistant_config(config: HomeAssistantConfig, user=Depends(require_jwt)):
    """Update Home Assistant configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    current = get_config()
    token = config.token
    if token == "********":
        token = current.get("token", "")

    content = f"""# Home Assistant configuration
ha_url = "{config.ha_url}"
token = "{token}"
container_name = "{config.container_name}"
container_type = "{config.container_type}"
image = "{config.image}"
port = {config.port}
timezone = "{config.timezone}"
"""
    CONFIG_FILE.write_text(content)
    CONFIG_FILE.chmod(0o600)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")

    return {"success": True}


# ============================================================================
# Entity Management
# ============================================================================

@router.get("/entities")
async def get_entities(
    domain: Optional[str] = None,
    user=Depends(require_jwt)
):
    """Get list of all entities."""
    if not is_running():
        return {"entities": [], "error": "Home Assistant not running"}

    cfg = get_config()
    if not cfg.get("token"):
        return {"entities": [], "error": "API token not configured"}

    try:
        states = await ha_api_request("states")
        entities = []

        for state in states if isinstance(states, list) else []:
            entity_id = state.get("entity_id", "")
            entity_domain = entity_id.split(".")[0] if "." in entity_id else ""

            if domain and entity_domain != domain:
                continue

            entities.append({
                "entity_id": entity_id,
                "domain": entity_domain,
                "state": state.get("state"),
                "friendly_name": state.get("attributes", {}).get("friendly_name", entity_id),
                "last_changed": state.get("last_changed"),
                "attributes": state.get("attributes", {}),
            })

        return {"entities": entities}
    except Exception as e:
        log.error(f"Failed to get entities: {e}")
        return {"entities": [], "error": str(e)}


@router.get("/entity/{entity_id:path}")
async def get_entity(entity_id: str, user=Depends(require_jwt)):
    """Get entity details."""
    if not is_running():
        raise HTTPException(503, "Home Assistant not running")

    cfg = get_config()
    if not cfg.get("token"):
        raise HTTPException(400, "API token not configured")

    try:
        state = await ha_api_request(f"states/{entity_id}")
        return state
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/entity/{entity_id:path}/command")
async def send_entity_command(
    entity_id: str,
    command: EntityCommand,
    user=Depends(require_jwt)
):
    """Send command to entity."""
    if not is_running():
        raise HTTPException(503, "Home Assistant not running")

    try:
        data = command.data or {}
        data["entity_id"] = entity_id

        await ha_api_request(
            f"services/{command.domain}/{command.service}",
            "POST",
            data
        )

        log.info(f"Command {command.domain}.{command.service} sent to {entity_id} by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Device Management
# ============================================================================

@router.get("/devices")
async def get_devices(user=Depends(require_jwt)):
    """Get list of all devices."""
    if not is_running():
        return {"devices": [], "error": "Home Assistant not running"}

    cfg = get_config()
    if not cfg.get("token"):
        return {"devices": [], "error": "API token not configured"}

    try:
        # HA doesn't have a direct devices API, we aggregate from entities
        states = await ha_api_request("states")
        devices = {}

        for state in states if isinstance(states, list) else []:
            attrs = state.get("attributes", {})
            device_id = attrs.get("device_id")

            if device_id and device_id not in devices:
                devices[device_id] = {
                    "device_id": device_id,
                    "name": attrs.get("friendly_name", device_id),
                    "manufacturer": attrs.get("manufacturer", "Unknown"),
                    "model": attrs.get("model", "Unknown"),
                    "entities": []
                }

            if device_id:
                devices[device_id]["entities"].append(state.get("entity_id"))

        return {"devices": list(devices.values())}
    except Exception as e:
        log.error(f"Failed to get devices: {e}")
        return {"devices": [], "error": str(e)}


# ============================================================================
# Integration Management
# ============================================================================

@router.get("/integrations")
async def get_integrations(user=Depends(require_jwt)):
    """Get list of integrations."""
    if not is_running():
        return {"integrations": [], "error": "Home Assistant not running"}

    # Check for custom components
    config_dir = DATA_PATH / "config" / "custom_components"
    integrations = []

    if config_dir.exists():
        for comp in config_dir.iterdir():
            if comp.is_dir():
                manifest = comp / "manifest.json"
                if manifest.exists():
                    try:
                        data = json.loads(manifest.read_text())
                        integrations.append({
                            "domain": data.get("domain"),
                            "name": data.get("name"),
                            "version": data.get("version"),
                            "type": "custom"
                        })
                    except Exception:
                        pass

    return {"integrations": integrations, "count": len(integrations)}


@router.post("/integration/install")
async def install_integration(
    req: IntegrationInstall,
    user=Depends(require_jwt)
):
    """Install an integration (placeholder - requires HA frontend)."""
    log.info(f"Integration install requested: {req.integration} by {user.get('sub', 'unknown')}")
    return {
        "success": False,
        "error": "Integration installation requires Home Assistant frontend or HACS"
    }


# ============================================================================
# Automation Management
# ============================================================================

@router.get("/automations")
async def get_automations(user=Depends(require_jwt)):
    """Get list of automations."""
    if not is_running():
        return {"automations": [], "error": "Home Assistant not running"}

    cfg = get_config()
    if not cfg.get("token"):
        return {"automations": [], "error": "API token not configured"}

    try:
        states = await ha_api_request("states")
        automations = []

        for state in states if isinstance(states, list) else []:
            entity_id = state.get("entity_id", "")
            if entity_id.startswith("automation."):
                attrs = state.get("attributes", {})
                automations.append({
                    "entity_id": entity_id,
                    "name": attrs.get("friendly_name", entity_id),
                    "state": state.get("state"),
                    "last_triggered": attrs.get("last_triggered"),
                    "mode": attrs.get("mode", "single"),
                })

        return {"automations": automations}
    except Exception as e:
        log.error(f"Failed to get automations: {e}")
        return {"automations": [], "error": str(e)}


@router.post("/automation/toggle")
async def toggle_automation(
    req: AutomationToggle,
    user=Depends(require_jwt)
):
    """Enable/disable an automation."""
    if not is_running():
        raise HTTPException(503, "Home Assistant not running")

    try:
        service = "turn_on" if req.enabled else "turn_off"
        await ha_api_request(
            f"services/automation/{service}",
            "POST",
            {"entity_id": req.automation_id}
        )
        log.info(f"Automation {req.automation_id} {'enabled' if req.enabled else 'disabled'} by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Scene Management
# ============================================================================

@router.get("/scenes")
async def get_scenes(user=Depends(require_jwt)):
    """Get list of scenes."""
    if not is_running():
        return {"scenes": [], "error": "Home Assistant not running"}

    cfg = get_config()
    if not cfg.get("token"):
        return {"scenes": [], "error": "API token not configured"}

    try:
        states = await ha_api_request("states")
        scenes = []

        for state in states if isinstance(states, list) else []:
            entity_id = state.get("entity_id", "")
            if entity_id.startswith("scene."):
                attrs = state.get("attributes", {})
                scenes.append({
                    "entity_id": entity_id,
                    "name": attrs.get("friendly_name", entity_id),
                    "icon": attrs.get("icon"),
                })

        return {"scenes": scenes}
    except Exception as e:
        log.error(f"Failed to get scenes: {e}")
        return {"scenes": [], "error": str(e)}


@router.post("/scene/{scene_id:path}/activate")
async def activate_scene(scene_id: str, user=Depends(require_jwt)):
    """Activate a scene."""
    if not is_running():
        raise HTTPException(503, "Home Assistant not running")

    try:
        await ha_api_request(
            "services/scene/turn_on",
            "POST",
            {"entity_id": scene_id}
        )
        log.info(f"Scene {scene_id} activated by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Add-on Management (HACS)
# ============================================================================

@router.get("/addons")
async def get_addons(user=Depends(require_jwt)):
    """Get list of add-ons / HACS integrations."""
    if not is_running():
        return {"addons": [], "error": "Home Assistant not running"}

    # Check for HACS
    hacs_dir = DATA_PATH / "config" / "custom_components" / "hacs"
    hacs_installed = hacs_dir.exists()

    return {
        "addons": [],
        "hacs_installed": hacs_installed,
        "note": "Add-on management requires HACS or Home Assistant Supervisor"
    }


@router.post("/addon/install")
async def install_addon(
    req: AddonInstall,
    user=Depends(require_jwt)
):
    """Install an add-on (placeholder - requires HA Supervisor or HACS)."""
    log.info(f"Add-on install requested: {req.addon_slug} by {user.get('sub', 'unknown')}")
    return {
        "success": False,
        "error": "Add-on installation requires Home Assistant Supervisor or HACS"
    }


@router.post("/hacs/install")
async def install_hacs(user=Depends(require_jwt)):
    """Install HACS (Home Assistant Community Store)."""
    if not is_running():
        raise HTTPException(503, "Home Assistant not running")

    rt = detect_runtime()
    cfg = get_config()
    container = cfg.get("container_name", "homeassistant")

    try:
        if rt == "lxc":
            result = subprocess.run(
                ["lxc-attach", "-n", LXC_NAME, "--", "bash", "-c",
                 "cd /srv/homeassistant/config && wget -O - https://get.hacs.xyz | bash -"],
                capture_output=True, text=True, timeout=120
            )
        else:
            config_dir = DATA_PATH / "config"
            result = subprocess.run(
                ["bash", "-c", f"cd {config_dir} && wget -O - https://get.hacs.xyz | bash -"],
                capture_output=True, text=True, timeout=120
            )

        if result.returncode == 0:
            log.info(f"HACS installed by {user.get('sub', 'unknown')}")
            return {"success": True, "message": "HACS installed. Restart Home Assistant to complete."}
        else:
            return {"success": False, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Backup Management
# ============================================================================

@router.post("/backup/create")
async def create_backup(
    req: BackupCreate,
    user=Depends(require_jwt)
):
    """Create a backup."""
    backup_dir = DATA_PATH / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = req.name or f"ha_backup_{timestamp}"
    backup_file = backup_dir / f"{backup_name}.tar.gz"

    config_dir = DATA_PATH / "config"

    try:
        if config_dir.exists():
            result = subprocess.run(
                ["tar", "-czf", str(backup_file), "-C", str(config_dir), "."],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}
        else:
            return {"success": False, "error": "Config directory not found"}

        log.info(f"Backup created: {backup_name} by {user.get('sub', 'unknown')}")
        return {
            "success": True,
            "backup_name": backup_name,
            "backup_path": str(backup_file),
            "size": backup_file.stat().st_size
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/backups")
async def list_backups(user=Depends(require_jwt)):
    """List available backups."""
    backup_dir = DATA_PATH / "backups"
    backups = []

    if backup_dir.exists():
        for f in backup_dir.glob("*.tar.gz"):
            stat = f.stat()
            backups.append({
                "name": f.stem,
                "file": f.name,
                "path": str(f),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })

    return {"backups": sorted(backups, key=lambda x: x["created"], reverse=True)}


@router.post("/backup/restore")
async def restore_backup(path: str = Query(...), user=Depends(require_jwt)):
    """Restore from backup."""
    backup_path = Path(path)
    if not backup_path.exists():
        raise HTTPException(404, "Backup file not found")

    config_dir = DATA_PATH / "config"

    try:
        # Clear config directory (keep .storage if exists)
        if config_dir.exists():
            for item in config_dir.iterdir():
                if item.name != ".storage":
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()

        config_dir.mkdir(parents=True, exist_ok=True)

        # Extract backup
        result = subprocess.run(
            ["tar", "-xzf", str(backup_path), "-C", str(config_dir)],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr}

        log.info(f"Backup restored from {path} by {user.get('sub', 'unknown')}")
        return {"success": True, "message": "Backup restored. Restart Home Assistant to apply."}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Container/LXC Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container/LXC status."""
    rt = detect_runtime()
    cfg = get_config()
    container = cfg.get("container_name", "homeassistant")

    status_info = {
        "running": is_running(),
        "runtime": rt,
        "container_name": container,
        "container_type": cfg.get("container_type", "docker"),
        "image": cfg.get("image"),
        "container_ip": None,
        "memory": None,
        "cpu": None,
    }

    if rt and is_running():
        try:
            if rt == "lxc":
                status_info["container_ip"] = lxc_get_ip()
                result = subprocess.run(
                    ["lxc-info", "-n", LXC_NAME],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if "Memory use:" in line:
                        status_info["memory"] = line.split(":")[-1].strip()
            else:
                result = subprocess.run(
                    [rt, "stats", "--no-stream", "--format",
                     "{{.MemUsage}} {{.CPUPerc}}", container],
                    capture_output=True, text=True, timeout=5
                )
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    status_info["memory"] = parts[0]
                    status_info["cpu"] = parts[-1]
        except Exception:
            pass

    return status_info


@router.post("/container/install")
async def install_container(user=Depends(require_jwt)):
    """Pull Home Assistant container image or create LXC."""
    rt = detect_runtime()
    cfg = get_config()

    if not rt:
        return {"success": False, "error": "No container runtime available"}

    if rt == "lxc":
        # Check if already exists
        if lxc_exists():
            return {"success": True, "message": "LXC container already exists"}

        # Create LXC container
        try:
            DATA_PATH.mkdir(parents=True, exist_ok=True)
            config_dir = DATA_PATH / "config"
            config_dir.mkdir(exist_ok=True)

            result = subprocess.run(
                ["lxc-create", "-n", LXC_NAME, "-t", "download", "--",
                 "-d", "debian", "-r", "bookworm", "-a", "amd64"],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            log.info(f"LXC container created by {user.get('sub', 'unknown')}")
            return {"success": True, "message": "LXC container created. Run /container/start to initialize."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Docker/Podman
    image = cfg.get("image", "ghcr.io/home-assistant/home-assistant:stable")
    log.info(f"Pulling Home Assistant image by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}


@router.post("/container/start")
async def start_container(user=Depends(require_jwt)):
    """Start Home Assistant container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    cfg = get_config()

    if not rt:
        return {"success": False, "error": "No container runtime available"}

    container = cfg.get("container_name", "homeassistant")
    image = cfg.get("image", "ghcr.io/home-assistant/home-assistant:stable")
    port = cfg.get("port", 8123)
    tz = cfg.get("timezone", "UTC")

    # Ensure directories
    DATA_PATH.mkdir(parents=True, exist_ok=True)
    config_dir = DATA_PATH / "config"
    config_dir.mkdir(exist_ok=True)

    if rt == "lxc":
        if not lxc_exists():
            return {"success": False, "error": "LXC container not created. Run /container/install first."}

        try:
            result = subprocess.run(
                ["lxc-start", "-n", LXC_NAME],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            # Wait for IP
            for _ in range(30):
                await asyncio.sleep(1)
                if lxc_get_ip():
                    break

            await asyncio.sleep(5)

            log.info(f"Home Assistant LXC started by {user.get('sub', 'unknown')}")
            return {"success": True, "ip": lxc_get_ip()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Docker/Podman
    cmd = [
        rt, "run", "-d",
        "--name", container,
        "--privileged",
        "-v", f"{config_dir}:/config",
        "-v", "/run/dbus:/run/dbus:ro",
        "-p", f"127.0.0.1:{port}:8123",
        "-e", f"TZ={tz}",
        "--restart", "unless-stopped",
        image,
    ]

    log.info(f"Starting Home Assistant by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        await asyncio.sleep(10)  # HA takes time to initialize

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Start timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/stop")
async def stop_container(user=Depends(require_jwt)):
    """Stop Home Assistant container."""
    rt = detect_runtime()
    cfg = get_config()

    if not rt:
        return {"success": False, "error": "No container runtime"}

    container = cfg.get("container_name", "homeassistant")
    log.info(f"Stopping Home Assistant by {user.get('sub', 'unknown')}")

    try:
        if rt == "lxc":
            subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=60)
        else:
            subprocess.run([rt, "stop", container], capture_output=True, timeout=30)
            subprocess.run([rt, "rm", "-f", container], capture_output=True, timeout=10)

        if not is_running():
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_container(user=Depends(require_jwt)):
    """Restart Home Assistant container."""
    await stop_container(user)
    await asyncio.sleep(2)
    return await start_container(user)


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Get recent logs."""
    rt = detect_runtime()
    cfg = get_config()
    logs = []

    if rt and is_running():
        container = cfg.get("container_name", "homeassistant")
        try:
            if rt == "lxc":
                result = subprocess.run(
                    ["lxc-attach", "-n", LXC_NAME, "--",
                     "journalctl", "-u", "homeassistant", "-n", str(lines), "--no-pager"],
                    capture_output=True, text=True, timeout=10
                )
            else:
                result = subprocess.run(
                    [rt, "logs", "--tail", str(lines), container],
                    capture_output=True, text=True, timeout=10
                )

            if result.stdout:
                logs = result.stdout.strip().split('\n')
            if result.stderr:
                logs.extend(result.stderr.strip().split('\n'))
        except Exception:
            pass

    # Fallback to log file
    if not logs:
        log_file = DATA_PATH / "config" / "home-assistant.log"
        if log_file.exists():
            try:
                with open(log_file) as f:
                    all_lines = f.readlines()
                    logs = [l.strip() for l in all_lines[-lines:]]
            except Exception:
                pass

    return {"logs": logs[-lines:] if logs else []}


app.include_router(router)
