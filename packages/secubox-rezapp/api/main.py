"""
SecuBox-Deb :: RezApp API
Application deployment and management module.
CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import subprocess
import json
import os
import asyncio
from datetime import datetime
from pathlib import Path

try:
    from secubox_core.auth import router as auth_router, require_jwt
except ImportError:
    # Fallback for development/testing
    from fastapi import APIRouter
    auth_router = APIRouter()
    def require_jwt():
        pass

app = FastAPI(title="SecuBox RezApp API", version="1.0.0")
app.include_router(auth_router)

# Directories
APP_DIR = Path("/var/lib/secubox/rezapp")
TEMPLATES_DIR = APP_DIR / "templates"
CACHE_FILE = Path("/var/cache/secubox/rezapp/stats.json")

# In-memory cache
_cache: Dict[str, Any] = {}


# Pydantic models
class AppDeploy(BaseModel):
    name: str
    template: Optional[str] = None
    image: Optional[str] = None
    runtime: str = "docker"  # docker or lxc
    ports: Optional[Dict[str, int]] = None  # host:container
    env: Optional[Dict[str, str]] = None
    volumes: Optional[Dict[str, str]] = None  # host:container
    memory: Optional[str] = "512m"
    cpus: Optional[float] = 1.0
    restart_policy: str = "unless-stopped"


class TemplateCreate(BaseModel):
    name: str
    description: str
    image: str
    runtime: str = "docker"
    default_ports: Optional[Dict[str, int]] = None
    default_env: Optional[Dict[str, str]] = None
    default_volumes: Optional[Dict[str, str]] = None
    default_memory: str = "512m"
    default_cpus: float = 1.0


def run_cmd(cmd: list, timeout: int = 60) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def is_docker_available() -> bool:
    """Check if Docker is available."""
    _, _, code = run_cmd(["docker", "info"])
    return code == 0


def is_lxc_available() -> bool:
    """Check if LXC is available."""
    _, _, code = run_cmd(["which", "lxc-ls"])
    return code == 0


def get_docker_containers() -> List[Dict]:
    """List all Docker containers managed by rezapp."""
    containers = []
    stdout, _, code = run_cmd([
        "docker", "ps", "-a",
        "--filter", "label=secubox.rezapp=true",
        "--format", '{{json .}}'
    ])

    if code != 0:
        return containers

    for line in stdout.strip().split('\n'):
        if line:
            try:
                data = json.loads(line)
                containers.append({
                    "id": data.get("ID", ""),
                    "name": data.get("Names", ""),
                    "image": data.get("Image", ""),
                    "status": data.get("Status", ""),
                    "state": data.get("State", ""),
                    "ports": data.get("Ports", ""),
                    "created": data.get("CreatedAt", ""),
                    "runtime": "docker"
                })
            except json.JSONDecodeError:
                continue

    return containers


def get_container_stats(container_id: str) -> Dict:
    """Get resource usage for a Docker container."""
    stdout, _, code = run_cmd([
        "docker", "stats", container_id,
        "--no-stream", "--format", '{{json .}}'
    ])

    if code != 0 or not stdout.strip():
        return {}

    try:
        data = json.loads(stdout.strip())
        return {
            "cpu_percent": data.get("CPUPerc", "0%"),
            "memory_usage": data.get("MemUsage", ""),
            "memory_percent": data.get("MemPerc", "0%"),
            "net_io": data.get("NetIO", ""),
            "block_io": data.get("BlockIO", ""),
            "pids": data.get("PIDs", "0")
        }
    except json.JSONDecodeError:
        return {}


def get_container_logs(container_name: str, lines: int = 100) -> str:
    """Get container logs."""
    stdout, stderr, code = run_cmd([
        "docker", "logs", container_name,
        "--tail", str(lines), "--timestamps"
    ], timeout=30)

    if code != 0:
        return stderr or "Failed to get logs"

    return stdout


def load_templates() -> List[Dict]:
    """Load application templates from disk."""
    templates = []
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    # Built-in templates
    builtin = [
        {
            "name": "nginx",
            "description": "Nginx web server",
            "image": "nginx:alpine",
            "runtime": "docker",
            "default_ports": {"80": 80, "443": 443},
            "default_memory": "256m",
            "default_cpus": 0.5,
            "builtin": True
        },
        {
            "name": "redis",
            "description": "Redis in-memory data store",
            "image": "redis:alpine",
            "runtime": "docker",
            "default_ports": {"6379": 6379},
            "default_memory": "256m",
            "default_cpus": 0.5,
            "builtin": True
        },
        {
            "name": "postgres",
            "description": "PostgreSQL database",
            "image": "postgres:15-alpine",
            "runtime": "docker",
            "default_ports": {"5432": 5432},
            "default_env": {"POSTGRES_PASSWORD": "changeme"},
            "default_memory": "512m",
            "default_cpus": 1.0,
            "builtin": True
        },
        {
            "name": "mariadb",
            "description": "MariaDB database",
            "image": "mariadb:11",
            "runtime": "docker",
            "default_ports": {"3306": 3306},
            "default_env": {"MARIADB_ROOT_PASSWORD": "changeme"},
            "default_memory": "512m",
            "default_cpus": 1.0,
            "builtin": True
        },
        {
            "name": "mongodb",
            "description": "MongoDB NoSQL database",
            "image": "mongo:7",
            "runtime": "docker",
            "default_ports": {"27017": 27017},
            "default_memory": "512m",
            "default_cpus": 1.0,
            "builtin": True
        },
        {
            "name": "rabbitmq",
            "description": "RabbitMQ message broker",
            "image": "rabbitmq:3-management-alpine",
            "runtime": "docker",
            "default_ports": {"5672": 5672, "15672": 15672},
            "default_memory": "512m",
            "default_cpus": 1.0,
            "builtin": True
        },
        {
            "name": "minio",
            "description": "MinIO S3-compatible object storage",
            "image": "minio/minio:latest",
            "runtime": "docker",
            "default_ports": {"9000": 9000, "9001": 9001},
            "default_env": {"MINIO_ROOT_USER": "admin", "MINIO_ROOT_PASSWORD": "changeme"},
            "default_memory": "512m",
            "default_cpus": 1.0,
            "builtin": True
        },
        {
            "name": "grafana",
            "description": "Grafana monitoring dashboard",
            "image": "grafana/grafana:latest",
            "runtime": "docker",
            "default_ports": {"3000": 3000},
            "default_memory": "256m",
            "default_cpus": 0.5,
            "builtin": True
        }
    ]
    templates.extend(builtin)

    # Load custom templates
    for template_file in TEMPLATES_DIR.glob("*.json"):
        try:
            with open(template_file) as f:
                template = json.load(f)
                template["builtin"] = False
                templates.append(template)
        except (json.JSONDecodeError, IOError):
            continue

    return templates


async def refresh_cache():
    """Background task to refresh stats cache."""
    global _cache
    while True:
        try:
            apps = get_docker_containers()
            stats = {}

            for app in apps:
                if app.get("state") == "running":
                    stats[app["name"]] = get_container_stats(app["id"])

            _cache = {
                "timestamp": datetime.now().isoformat(),
                "apps": apps,
                "stats": stats,
                "total": len(apps),
                "running": len([a for a in apps if a.get("state") == "running"])
            }

            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(_cache))
        except Exception:
            pass

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background tasks."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    asyncio.create_task(refresh_cache())


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "rezapp"}


@app.get("/status")
def get_status():
    """Get RezApp module status."""
    docker_ok = is_docker_available()
    lxc_ok = is_lxc_available()

    apps = get_docker_containers() if docker_ok else []
    running = len([a for a in apps if a.get("state") == "running"])

    return {
        "docker": {
            "available": docker_ok
        },
        "lxc": {
            "available": lxc_ok
        },
        "apps": {
            "total": len(apps),
            "running": running
        },
        "templates": {
            "count": len(load_templates())
        }
    }


@app.get("/apps")
def list_apps():
    """List all deployed applications."""
    apps = get_docker_containers()
    return {"apps": apps}


@app.get("/app/{name}")
def get_app(name: str):
    """Get application details."""
    apps = get_docker_containers()

    for app in apps:
        if app["name"] == name:
            # Get detailed stats
            if app.get("state") == "running":
                app["stats"] = get_container_stats(app["id"])

            # Get inspect data
            stdout, _, code = run_cmd(["docker", "inspect", name])
            if code == 0:
                try:
                    inspect = json.loads(stdout)
                    if inspect:
                        app["config"] = inspect[0].get("Config", {})
                        app["network"] = inspect[0].get("NetworkSettings", {})
                        app["mounts"] = inspect[0].get("Mounts", [])
                except json.JSONDecodeError:
                    pass

            return app

    raise HTTPException(status_code=404, detail="Application not found")


@app.post("/app/deploy")
def deploy_app(config: AppDeploy):
    """Deploy a new application."""
    if not is_docker_available():
        raise HTTPException(status_code=503, detail="Docker not available")

    # Check if app already exists
    apps = get_docker_containers()
    for app in apps:
        if app["name"] == config.name:
            raise HTTPException(status_code=409, detail="Application already exists")

    # Build docker run command
    cmd = ["docker", "run", "-d", "--name", config.name]
    cmd.extend(["--label", "secubox.rezapp=true"])
    cmd.extend(["--restart", config.restart_policy])

    # Memory and CPU limits
    if config.memory:
        cmd.extend(["--memory", config.memory])
    if config.cpus:
        cmd.extend(["--cpus", str(config.cpus)])

    # Port mappings
    if config.ports:
        for host_port, container_port in config.ports.items():
            cmd.extend(["-p", f"{host_port}:{container_port}"])

    # Environment variables
    if config.env:
        for key, value in config.env.items():
            cmd.extend(["-e", f"{key}={value}"])

    # Volume mounts
    if config.volumes:
        for host_path, container_path in config.volumes.items():
            cmd.extend(["-v", f"{host_path}:{container_path}"])

    # Determine image
    image = config.image
    if not image and config.template:
        templates = load_templates()
        for t in templates:
            if t["name"] == config.template:
                image = t["image"]
                break

    if not image:
        raise HTTPException(status_code=400, detail="No image or template specified")

    cmd.append(image)

    stdout, stderr, code = run_cmd(cmd, timeout=120)

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to deploy: {stderr}")

    return {
        "status": "deployed",
        "name": config.name,
        "container_id": stdout.strip()[:12]
    }


@app.post("/app/undeploy")
def undeploy_app(name: str):
    """Undeploy (remove) an application."""
    if not is_docker_available():
        raise HTTPException(status_code=503, detail="Docker not available")

    # Stop container
    run_cmd(["docker", "stop", name], timeout=30)

    # Remove container
    stdout, stderr, code = run_cmd(["docker", "rm", name])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to remove: {stderr}")

    return {"status": "undeployed", "name": name}


@app.get("/app/{name}/logs")
def get_app_logs(name: str, lines: int = 100):
    """Get application logs."""
    logs = get_container_logs(name, lines)
    return {"name": name, "logs": logs, "lines": lines}


@app.post("/app/{name}/restart")
def restart_app(name: str):
    """Restart an application."""
    stdout, stderr, code = run_cmd(["docker", "restart", name])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")

    return {"status": "restarted", "name": name}


@app.post("/app/{name}/start")
def start_app(name: str):
    """Start a stopped application."""
    stdout, stderr, code = run_cmd(["docker", "start", name])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")

    return {"status": "started", "name": name}


@app.post("/app/{name}/stop")
def stop_app(name: str):
    """Stop a running application."""
    stdout, stderr, code = run_cmd(["docker", "stop", name])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")

    return {"status": "stopped", "name": name}


@app.get("/templates")
def list_templates():
    """List available application templates."""
    templates = load_templates()
    return {"templates": templates}


@app.get("/templates/{name}")
def get_template(name: str):
    """Get a specific template."""
    templates = load_templates()
    for t in templates:
        if t["name"] == name:
            return t
    raise HTTPException(status_code=404, detail="Template not found")


@app.post("/templates")
def create_template(template: TemplateCreate):
    """Create a custom application template."""
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    template_file = TEMPLATES_DIR / f"{template.name}.json"
    if template_file.exists():
        raise HTTPException(status_code=409, detail="Template already exists")

    template_data = template.dict()
    template_data["created"] = datetime.now().isoformat()

    with open(template_file, "w") as f:
        json.dump(template_data, f, indent=2)

    return {"status": "created", "name": template.name}


@app.delete("/templates/{name}")
def delete_template(name: str):
    """Delete a custom template."""
    template_file = TEMPLATES_DIR / f"{name}.json"

    if not template_file.exists():
        raise HTTPException(status_code=404, detail="Template not found")

    template_file.unlink()
    return {"status": "deleted", "name": name}


@app.get("/stats")
def get_stats():
    """Get cached application statistics."""
    if _cache:
        return _cache

    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except json.JSONDecodeError:
            pass

    # Generate fresh stats
    apps = get_docker_containers()
    stats = {}

    for app in apps:
        if app.get("state") == "running":
            stats[app["name"]] = get_container_stats(app["id"])

    return {
        "timestamp": datetime.now().isoformat(),
        "apps": apps,
        "stats": stats,
        "total": len(apps),
        "running": len([a for a in apps if a.get("state") == "running"])
    }


@app.get("/images")
def list_images():
    """List available Docker images."""
    stdout, _, code = run_cmd([
        "docker", "images",
        "--format", '{{json .}}'
    ])

    if code != 0:
        return {"images": []}

    images = []
    for line in stdout.strip().split('\n'):
        if line:
            try:
                data = json.loads(line)
                images.append({
                    "id": data.get("ID", ""),
                    "repository": data.get("Repository", ""),
                    "tag": data.get("Tag", ""),
                    "size": data.get("Size", ""),
                    "created": data.get("CreatedSince", "")
                })
            except json.JSONDecodeError:
                continue

    return {"images": images}


@app.post("/images/pull")
def pull_image(image: str):
    """Pull a Docker image."""
    stdout, stderr, code = run_cmd(["docker", "pull", image], timeout=300)

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to pull image: {stderr}")

    return {"status": "pulled", "image": image}
