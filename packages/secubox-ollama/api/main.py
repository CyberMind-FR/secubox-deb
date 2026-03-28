"""secubox-ollama — FastAPI application for local AI inference.

Ported from OpenWRT luci-app-ollama RPCD backend.
Provides Ollama container management and API proxy.
"""
import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
import httpx

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-ollama", version="1.0.0", root_path="/api/v1/ollama")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("ollama")

# Configuration
CONFIG_FILE = Path("/etc/secubox/ollama.toml")
DEFAULT_CONFIG = {
    "api_port": 11434,
    "data_path": "/srv/ollama",
    "memory_limit": "4g",
    "gpu_enabled": False,
}


# ============================================================================
# Models
# ============================================================================

class OllamaConfig(BaseModel):
    api_port: int = 11434
    data_path: str = "/srv/ollama"
    memory_limit: str = "4g"
    gpu_enabled: bool = False


class ModelInfo(BaseModel):
    name: str
    size: int = 0
    modified: Optional[str] = None
    digest: Optional[str] = None


class ChatRequest(BaseModel):
    model: str
    message: str
    system: Optional[str] = None


class GenerateRequest(BaseModel):
    model: str
    prompt: str
    system: Optional[str] = None


class ModelPullRequest(BaseModel):
    name: str


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load ollama configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def detect_runtime() -> Optional[str]:
    """Detect container runtime (podman or docker)."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def is_running() -> bool:
    """Check if Ollama container is running."""
    rt = detect_runtime()
    if not rt:
        return False
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        return "ollama" in result.stdout.split()
    except Exception:
        return False


def get_ollama_url() -> str:
    """Get Ollama API URL."""
    cfg = get_config()
    port = cfg.get("api_port", 11434)
    return f"http://127.0.0.1:{port}"


async def ollama_request(method: str, endpoint: str, json_data: dict = None) -> dict:
    """Make request to Ollama API."""
    url = f"{get_ollama_url()}{endpoint}"
    async with httpx.AsyncClient(timeout=120.0) as client:
        if method == "GET":
            resp = await client.get(url)
        else:
            resp = await client.post(url, json=json_data)
        resp.raise_for_status()
        return resp.json()


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "ollama"}


@router.get("/status")
async def status():
    """Get Ollama service status."""
    cfg = get_config()
    rt = detect_runtime()
    running = is_running()
    uptime = 0

    if running and rt:
        try:
            result = subprocess.run(
                [rt, "ps", "--filter", "name=ollama", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=5
            )
            status_str = result.stdout.strip().split('\n')[0] if result.stdout else ""
            if "minute" in status_str:
                uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 60
            elif "hour" in status_str:
                uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 3600
            elif "second" in status_str:
                uptime = int(''.join(filter(str.isdigit, status_str.split()[1])))
        except Exception:
            pass

    return {
        "running": running,
        "uptime": uptime,
        "api_port": cfg.get("api_port", 11434),
        "memory_limit": cfg.get("memory_limit", "4g"),
        "data_path": cfg.get("data_path", "/srv/ollama"),
        "runtime": rt or "none",
        "gpu_enabled": cfg.get("gpu_enabled", False),
    }


# ============================================================================
# Protected Endpoints (JWT required)
# ============================================================================

@router.get("/config")
async def get_ollama_config(user=Depends(require_jwt)):
    """Get Ollama configuration."""
    return get_config()


@router.post("/config")
async def set_ollama_config(config: OllamaConfig, user=Depends(require_jwt)):
    """Update Ollama configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    content = f"""# Ollama configuration
api_port = {config.api_port}
data_path = "{config.data_path}"
memory_limit = "{config.memory_limit}"
gpu_enabled = {str(config.gpu_enabled).lower()}
"""
    CONFIG_FILE.write_text(content)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


@router.get("/models")
async def list_models(user=Depends(require_jwt)):
    """List installed models."""
    if not is_running():
        return {"models": [], "error": "Ollama not running"}

    try:
        data = await ollama_request("GET", "/api/tags")
        models = []
        for m in data.get("models", []):
            models.append(ModelInfo(
                name=m.get("name", ""),
                size=m.get("size", 0),
                modified=m.get("modified_at"),
                digest=m.get("digest"),
            ))
        return {"models": [m.dict() for m in models]}
    except Exception as e:
        log.error(f"Failed to list models: {e}")
        return {"models": [], "error": str(e)}


@router.get("/models/{name}")
async def get_model_info(name: str, user=Depends(require_jwt)):
    """Get model details."""
    if not is_running():
        raise HTTPException(503, "Ollama not running")

    rt = detect_runtime()
    if not rt:
        raise HTTPException(503, "No container runtime")

    try:
        result = subprocess.run(
            [rt, "exec", "ollama", "ollama", "show", name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            raise HTTPException(404, "Model not found")

        info = {"name": name}
        for line in result.stdout.split('\n'):
            if line.startswith("parameters"):
                info["parameters"] = line.split()[1] if len(line.split()) > 1 else "unknown"
            elif line.startswith("family"):
                info["family"] = line.split()[1] if len(line.split()) > 1 else "unknown"
            elif line.startswith("format"):
                info["format"] = line.split()[1] if len(line.split()) > 1 else "unknown"
            elif line.startswith("quantization"):
                info["quantization"] = line.split()[1] if len(line.split()) > 1 else "unknown"

        return info
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Timeout getting model info")


@router.post("/models/pull")
async def pull_model(req: ModelPullRequest, user=Depends(require_jwt)):
    """Pull a model from Ollama registry."""
    if not is_running():
        raise HTTPException(503, "Ollama not running")

    rt = detect_runtime()
    if not rt:
        raise HTTPException(503, "No container runtime")

    log.info(f"Pulling model {req.name} by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "exec", "ollama", "ollama", "pull", req.name],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            return {"success": True, "model": req.name}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout - model may be too large"}


@router.delete("/models/{name}")
async def remove_model(name: str, user=Depends(require_jwt)):
    """Remove a model."""
    if not is_running():
        raise HTTPException(503, "Ollama not running")

    rt = detect_runtime()
    if not rt:
        raise HTTPException(503, "No container runtime")

    log.info(f"Removing model {name} by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "exec", "ollama", "ollama", "rm", name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Remove timeout"}


@router.post("/chat")
async def chat(req: ChatRequest, user=Depends(require_jwt)):
    """Chat completion."""
    if not is_running():
        raise HTTPException(503, "Ollama not running")

    messages = []
    if req.system:
        messages.append({"role": "system", "content": req.system})
    messages.append({"role": "user", "content": req.message})

    try:
        data = await ollama_request("POST", "/api/chat", {
            "model": req.model,
            "messages": messages,
            "stream": False,
        })
        return {
            "response": data.get("message", {}).get("content", ""),
            "model": req.model,
            "done": data.get("done", True),
        }
    except httpx.HTTPStatusError as e:
        log.error(f"Chat error: {e}")
        return {"response": "", "error": str(e)}
    except Exception as e:
        log.error(f"Chat error: {e}")
        return {"response": "", "error": str(e)}


@router.post("/generate")
async def generate(req: GenerateRequest, user=Depends(require_jwt)):
    """Text generation."""
    if not is_running():
        raise HTTPException(503, "Ollama not running")

    payload = {
        "model": req.model,
        "prompt": req.prompt,
        "stream": False,
    }
    if req.system:
        payload["system"] = req.system

    try:
        data = await ollama_request("POST", "/api/generate", payload)
        return {
            "text": data.get("response", ""),
            "model": req.model,
            "done": data.get("done", True),
        }
    except Exception as e:
        log.error(f"Generate error: {e}")
        return {"text": "", "error": str(e)}


@router.get("/system")
async def system_info(user=Depends(require_jwt)):
    """Get system resource info."""
    cfg = get_config()
    rt = detect_runtime()

    mem_total = mem_used = mem_pct = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_free = int(line.split()[1])
                    mem_used = mem_total - mem_free
                    mem_pct = (mem_used * 100) // mem_total if mem_total else 0
    except Exception:
        pass

    disk_total = disk_used = disk_pct = 0
    data_path = cfg.get("data_path", "/srv/ollama")
    try:
        import os
        st = os.statvfs(data_path if Path(data_path).exists() else "/")
        disk_total = (st.f_blocks * st.f_frsize) // 1024
        disk_used = ((st.f_blocks - st.f_bfree) * st.f_frsize) // 1024
        disk_pct = (disk_used * 100) // disk_total if disk_total else 0
    except Exception:
        pass

    container_mem = "0"
    container_cpu = "0%"
    if is_running() and rt:
        try:
            result = subprocess.run(
                [rt, "stats", "--no-stream", "--format", "{{.MemUsage}} {{.CPUPerc}}", "ollama"],
                capture_output=True, text=True, timeout=5
            )
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                container_mem = parts[0]
                container_cpu = parts[-1]
        except Exception:
            pass

    return {
        "memory": {
            "total_kb": mem_total,
            "used_kb": mem_used,
            "percent": mem_pct,
        },
        "disk": {
            "total_kb": disk_total,
            "used_kb": disk_used,
            "percent": disk_pct,
            "path": data_path,
        },
        "container": {
            "memory": container_mem,
            "cpu": container_cpu,
        },
    }


@router.get("/logs")
async def get_logs(lines: int = 50, user=Depends(require_jwt)):
    """Get recent container logs."""
    rt = detect_runtime()
    if not rt:
        return {"logs": []}

    try:
        result = subprocess.run(
            [rt, "logs", "--tail", str(lines), "ollama"],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout.strip().split('\n') if result.stdout else []
        if result.stderr:
            logs.extend(result.stderr.strip().split('\n'))
        return {"logs": logs[-lines:]}
    except Exception:
        return {"logs": []}


# ============================================================================
# Service Control
# ============================================================================

@router.post("/start")
async def start_service(user=Depends(require_jwt)):
    """Start Ollama container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    data_path = Path(cfg.get("data_path", "/srv/ollama"))
    data_path.mkdir(parents=True, exist_ok=True)

    cmd = [
        rt, "run", "-d",
        "--name", "ollama",
        "-v", f"{data_path}:/root/.ollama",
        "-p", f"127.0.0.1:{cfg.get('api_port', 11434)}:11434",
        "--memory", cfg.get("memory_limit", "4g"),
        "--restart", "unless-stopped",
    ]

    if cfg.get("gpu_enabled") and rt == "docker":
        cmd.extend(["--gpus", "all"])

    cmd.append("ollama/ollama")

    log.info(f"Starting Ollama by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        await asyncio.sleep(3)

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Start timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/stop")
async def stop_service(user=Depends(require_jwt)):
    """Stop Ollama container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    log.info(f"Stopping Ollama by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", "ollama"], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", "ollama"], capture_output=True, timeout=10)

        if not is_running():
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restart")
async def restart_service(user=Depends(require_jwt)):
    """Restart Ollama container."""
    await stop_service(user)
    await asyncio.sleep(1)
    return await start_service(user)


app.include_router(router)
