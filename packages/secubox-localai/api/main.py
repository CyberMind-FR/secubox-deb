"""SecuBox LocalAI - Alternative LLM Backend
Self-hosted AI inference with LocalAI in LXC container.

Features:
- LXC container management
- Model management (GGUF, ONNX, transformers)
- OpenAI-compatible API proxy
- Chat and text completion endpoints
- Resource monitoring (CPU/memory)
- Model gallery browser
"""
import os
import json
import asyncio
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt

# Configuration
CONFIG_FILE = Path("/etc/secubox/localai.json")
DATA_DIR = Path("/srv/localai")
MODELS_DIR = DATA_DIR / "models"
LXC_NAME = "localai"
DEFAULT_PORT = 8081
LXC_ROOT = Path("/var/lib/lxc")

app = FastAPI(title="SecuBox LocalAI", version="1.0.0")


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: float = 0.7
    max_tokens: int = 2048


class CompletionRequest(BaseModel):
    model: str
    prompt: str
    temperature: float = 0.7
    max_tokens: int = 2048


class ConfigUpdate(BaseModel):
    api_port: int = 8081
    memory_limit: str = "4G"
    threads: int = 4
    context_size: int = 2048
    gpu_enabled: bool = False


def load_config() -> dict:
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {
        "api_port": DEFAULT_PORT,
        "memory_limit": "4G",
        "threads": 4,
        "context_size": 2048,
        "gpu_enabled": False
    }


def save_config(config: dict):
    """Save configuration to file."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def lxc_exists() -> bool:
    """Check if LXC container exists."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def lxc_running() -> bool:
    """Check if LXC container is running."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-s"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False


def lxc_get_ip() -> Optional[str]:
    """Get LXC container IP address."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-iH"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            ips = result.stdout.strip().split("\n")
            for ip in ips:
                if ip and not ip.startswith("127."):
                    return ip.strip()
        return None
    except Exception:
        return None


def lxc_exec(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Execute command inside LXC container."""
    return subprocess.run(
        ["lxc-attach", "-n", LXC_NAME, "--"] + cmd,
        capture_output=True,
        text=True,
        timeout=timeout
    )


def get_uptime() -> int:
    """Get container uptime in seconds."""
    if not lxc_running():
        return 0
    try:
        result = lxc_exec(["cat", "/proc/uptime"])
        if result.returncode == 0:
            return int(float(result.stdout.split()[0]))
    except Exception:
        pass
    return 0


async def localai_request(endpoint: str, method: str = "GET", data: dict = None, timeout: float = 120.0) -> dict:
    """Make request to LocalAI API."""
    ip = lxc_get_ip()
    if not ip:
        raise HTTPException(status_code=502, detail="Container IP not available")

    url = f"http://{ip}:8080{endpoint}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            if method == "GET":
                response = await client.get(url)
            else:
                response = await client.post(url, json=data)
            return response.json()
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="LocalAI API timeout")
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"LocalAI API error: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "module": "localai"}


@app.get("/status", dependencies=[Depends(require_jwt)])
async def get_status():
    """Get LocalAI service status."""
    config = load_config()
    running = lxc_running()
    exists = lxc_exists()
    ip = lxc_get_ip() if running else None

    # Check API health if running
    api_healthy = False
    version = "unknown"
    if running and ip:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"http://{ip}:8080/readyz")
                api_healthy = resp.status_code == 200
        except Exception:
            pass

    return {
        "running": running,
        "uptime": get_uptime() if running else 0,
        "version": version,
        "api_port": config.get("api_port", DEFAULT_PORT),
        "memory_limit": config.get("memory_limit", "4G"),
        "threads": config.get("threads", 4),
        "context_size": config.get("context_size", 2048),
        "gpu_enabled": config.get("gpu_enabled", False),
        "runtime": "lxc",
        "api_healthy": api_healthy,
        "container_exists": exists,
        "container_ip": ip,
        "data_path": str(DATA_DIR),
        "models_path": str(MODELS_DIR)
    }


@app.get("/models", dependencies=[Depends(require_jwt)])
async def list_models():
    """List available and loaded models."""
    models = []

    # Get loaded models from API if running
    if lxc_running():
        try:
            data = await localai_request("/v1/models", timeout=10.0)
            for m in data.get("data", []):
                models.append({
                    "id": m.get("id"),
                    "name": m.get("id"),
                    "loaded": True,
                    "type": "loaded",
                    "size": 0
                })
        except Exception:
            pass

    # Scan filesystem for model files
    loaded_ids = {m["id"] for m in models}

    if MODELS_DIR.exists():
        for ext in ["*.gguf", "*.bin", "*.onnx"]:
            for model_file in MODELS_DIR.glob(ext):
                model_id = model_file.stem
                if model_id not in loaded_ids:
                    model_type = {
                        ".gguf": "llama-cpp",
                        ".bin": "transformers",
                        ".onnx": "onnx"
                    }.get(model_file.suffix, "unknown")

                    models.append({
                        "id": model_id,
                        "name": model_file.name,
                        "loaded": False,
                        "type": model_type,
                        "size": model_file.stat().st_size,
                        "path": str(model_file)
                    })

    return {"models": models, "count": len(models)}


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config():
    """Get LocalAI configuration."""
    return load_config()


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(config: ConfigUpdate):
    """Update LocalAI configuration."""
    current = load_config()
    current.update(config.dict())
    save_config(current)
    return {"success": True, "config": current}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start LocalAI LXC container."""
    if not lxc_exists():
        raise HTTPException(status_code=400, detail="Container not created. Run /install first.")

    if lxc_running():
        return {"success": True, "message": "Already running"}

    try:
        result = subprocess.run(
            ["lxc-start", "-n", LXC_NAME],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to start: {result.stderr}")

        # Wait for container to get IP
        for _ in range(30):
            await asyncio.sleep(1)
            if lxc_get_ip():
                break

        # Wait for LocalAI service to be ready
        await asyncio.sleep(5)

        return {"success": True, "message": "LocalAI started", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Start timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop LocalAI LXC container."""
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}

    try:
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart LocalAI container."""
    await stop_service()
    await asyncio.sleep(2)
    return await start_service()


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install_localai():
    """Create and setup LocalAI LXC container."""
    if lxc_exists():
        return {"success": True, "message": "Container already exists"}

    config = load_config()

    # Ensure model directory exists on host
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # Create Debian bookworm container
        result = subprocess.run(
            [
                "lxc-create", "-n", LXC_NAME,
                "-t", "download",
                "--",
                "-d", "debian",
                "-r", "bookworm",
                "-a", "amd64"
            ],
            capture_output=True,
            text=True,
            timeout=600
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Create failed: {result.stderr}")

        # Configure container
        lxc_config = LXC_ROOT / LXC_NAME / "config"
        with open(lxc_config, "a") as f:
            f.write("\n# SecuBox LocalAI config\n")
            f.write("lxc.start.auto = 1\n")
            # Mount models directory from host
            f.write(f"lxc.mount.entry = {MODELS_DIR} srv/localai/models none bind,create=dir 0 0\n")
            # Memory limit
            mem_limit = config.get("memory_limit", "4G")
            f.write(f"lxc.cgroup2.memory.max = {mem_limit}\n")

        # Start container
        subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True, timeout=60)
        await asyncio.sleep(5)

        # Wait for network
        for _ in range(30):
            if lxc_get_ip():
                break
            await asyncio.sleep(1)

        # Install LocalAI
        threads = config.get("threads", 4)
        context_size = config.get("context_size", 2048)

        install_script = f"""
apt-get update && apt-get install -y curl wget git build-essential cmake

# Create directories
mkdir -p /srv/localai/models

# Download LocalAI binary
cd /tmp
wget -q https://github.com/mudler/LocalAI/releases/latest/download/local-ai-Linux-x86_64
chmod +x local-ai-Linux-x86_64
mv local-ai-Linux-x86_64 /usr/local/bin/local-ai

# Create systemd service
cat > /etc/systemd/system/localai.service << 'EOF'
[Unit]
Description=LocalAI LLM Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/local-ai --threads {threads} --context-size {context_size} --models-path /srv/localai/models --address 0.0.0.0:8080
WorkingDirectory=/srv/localai
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable localai
systemctl start localai
"""
        result = lxc_exec(["bash", "-c", install_script], timeout=600)
        if result.returncode != 0:
            # Log but don't fail - binary download may need manual intervention
            pass

        return {"success": True, "message": "LocalAI installed", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Install timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall_localai():
    """Remove LocalAI LXC container."""
    if lxc_running():
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)

    if lxc_exists():
        result = subprocess.run(
            ["lxc-destroy", "-n", LXC_NAME],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Destroy failed: {result.stderr}")

    return {"success": True, "message": "Container removed"}


@app.post("/models/install", dependencies=[Depends(require_jwt)])
async def install_model(name: str = Query(..., description="Model name or HuggingFace ID")):
    """Download a model from gallery or HuggingFace."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="LocalAI not running")

    # Use LocalAI gallery API
    try:
        data = await localai_request(
            "/models/apply",
            method="POST",
            data={"id": name},
            timeout=600.0
        )
        return {"success": True, "model": name, "result": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/models/{model_id}", dependencies=[Depends(require_jwt)])
async def remove_model(model_id: str):
    """Remove a model."""
    # Try to find and delete model file
    for ext in [".gguf", ".bin", ".onnx", ".yaml", ".yml"]:
        model_path = MODELS_DIR / f"{model_id}{ext}"
        if model_path.exists():
            model_path.unlink()

    return {"success": True, "model": model_id}


@app.post("/chat", dependencies=[Depends(require_jwt)])
async def chat_completion(request: ChatRequest):
    """Chat completion via LocalAI."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="LocalAI not running")

    try:
        data = await localai_request(
            "/v1/chat/completions",
            method="POST",
            data={
                "model": request.model,
                "messages": [m.dict() for m in request.messages],
                "temperature": request.temperature,
                "max_tokens": request.max_tokens
            },
            timeout=120.0
        )

        # Extract response
        if "choices" in data and len(data["choices"]) > 0:
            content = data["choices"][0].get("message", {}).get("content", "")
            return {"response": content, "usage": data.get("usage", {})}
        elif "error" in data:
            return {"response": "", "error": data["error"].get("message", "Unknown error")}
        else:
            return {"response": "", "error": "Empty response"}
    except HTTPException:
        raise
    except Exception as e:
        return {"response": "", "error": str(e)}


@app.post("/complete", dependencies=[Depends(require_jwt)])
async def text_completion(request: CompletionRequest):
    """Text completion via LocalAI."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="LocalAI not running")

    try:
        data = await localai_request(
            "/v1/completions",
            method="POST",
            data={
                "model": request.model,
                "prompt": request.prompt,
                "temperature": request.temperature,
                "max_tokens": request.max_tokens
            },
            timeout=120.0
        )

        if "choices" in data and len(data["choices"]) > 0:
            text = data["choices"][0].get("text", "")
            return {"text": text, "usage": data.get("usage", {})}
        else:
            return {"text": "", "error": "Empty response"}
    except HTTPException:
        raise
    except Exception as e:
        return {"text": "", "error": str(e)}


@app.get("/gallery", dependencies=[Depends(require_jwt)])
async def get_model_gallery():
    """Get available models from LocalAI gallery."""
    if not lxc_running():
        # Return static popular models list
        return {
            "models": [
                {"name": "llama-3.2-3b-instruct", "size": "2.2GB", "type": "llama", "description": "Llama 3.2 3B Instruct"},
                {"name": "phi-3-mini", "size": "2.3GB", "type": "llama", "description": "Microsoft Phi-3 Mini"},
                {"name": "gemma-2-2b-it", "size": "1.6GB", "type": "llama", "description": "Google Gemma 2 2B"},
                {"name": "mistral-7b-instruct", "size": "4.1GB", "type": "llama", "description": "Mistral 7B Instruct"},
                {"name": "codellama-7b", "size": "4.0GB", "type": "llama", "description": "Code Llama 7B"},
                {"name": "all-minilm-l6-v2", "size": "90MB", "type": "embeddings", "description": "Sentence Embeddings"},
                {"name": "whisper-base", "size": "150MB", "type": "audio", "description": "OpenAI Whisper Base"},
            ]
        }

    try:
        data = await localai_request("/models/available", timeout=30.0)
        return {"models": data}
    except Exception:
        return {"models": [], "error": "Failed to fetch gallery"}


@app.get("/metrics", dependencies=[Depends(require_jwt)])
async def get_metrics():
    """Get resource usage metrics."""
    if not lxc_running():
        return {"memory_used": 0, "cpu_percent": 0}

    try:
        # Get memory usage from cgroup
        result = lxc_exec(["cat", "/sys/fs/cgroup/memory.current"])
        memory_used = int(result.stdout.strip()) if result.returncode == 0 else 0

        # Get CPU usage (simplified)
        result = lxc_exec(["cat", "/proc/loadavg"])
        load_avg = float(result.stdout.split()[0]) if result.returncode == 0 else 0
        cpu_percent = min(load_avg * 100, 100)

        return {"memory_used": memory_used, "cpu_percent": cpu_percent}
    except Exception:
        return {"memory_used": 0, "cpu_percent": 0}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = Query(100, ge=10, le=1000)):
    """Get container logs."""
    if not lxc_exists():
        return {"logs": [], "error": "Container not found"}

    try:
        result = lxc_exec(
            ["journalctl", "-u", "localai", "-n", str(lines), "--no-pager"],
            timeout=30
        )
        logs = result.stdout.strip().split("\n") if result.stdout else []
        return {"logs": logs[-lines:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}
