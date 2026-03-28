"""SecuBox Redroid API - Android in container management."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os

app = FastAPI(title="SecuBox Redroid API", version="1.0.0")

REDROID_IMAGE = "redroid/redroid:12.0.0-latest"
REDROID_CONTAINER = "redroid"
ADB_PORT = 5555
SCRCPY_PORT = 5900


class RedroidConfig(BaseModel):
    image: str = REDROID_IMAGE
    gpu: bool = False
    memory: str = "4g"
    cpus: float = 2.0


def run_cmd(cmd: list, check: bool = True, timeout: int = 60) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def is_docker_installed() -> bool:
    """Check if Docker is installed."""
    _, _, code = run_cmd(["docker", "--version"], check=False)
    return code == 0


def is_container_running() -> bool:
    """Check if redroid container is running."""
    stdout, _, code = run_cmd([
        "docker", "inspect", "-f", "{{.State.Running}}", REDROID_CONTAINER
    ], check=False)
    return code == 0 and stdout.strip() == "true"


def container_exists() -> bool:
    """Check if redroid container exists."""
    _, _, code = run_cmd([
        "docker", "inspect", REDROID_CONTAINER
    ], check=False)
    return code == 0


def get_container_info() -> dict:
    """Get container info."""
    stdout, _, code = run_cmd([
        "docker", "inspect", REDROID_CONTAINER
    ], check=False)

    if code != 0:
        return {}

    try:
        info = json.loads(stdout)
        if info:
            c = info[0]
            return {
                "id": c.get("Id", "")[:12],
                "image": c.get("Config", {}).get("Image", ""),
                "state": c.get("State", {}).get("Status", ""),
                "created": c.get("Created", ""),
                "ports": c.get("NetworkSettings", {}).get("Ports", {})
            }
    except Exception:
        pass

    return {}


def is_adb_connected() -> bool:
    """Check if ADB can connect to container."""
    stdout, _, code = run_cmd([
        "adb", "devices"
    ], check=False)
    return f"localhost:{ADB_PORT}" in stdout or f"127.0.0.1:{ADB_PORT}" in stdout


@app.get("/health")
def health():
    return {"status": "ok", "service": "redroid"}


@app.get("/status")
def get_status():
    """Get Redroid status."""
    docker_ok = is_docker_installed()
    running = is_container_running() if docker_ok else False
    exists = container_exists() if docker_ok else False
    container_info = get_container_info() if exists else {}

    # Check ADB
    adb_connected = False
    if running:
        adb_connected = is_adb_connected()

    return {
        "docker_installed": docker_ok,
        "container_exists": exists,
        "running": running,
        "adb_connected": adb_connected,
        "adb_port": ADB_PORT,
        "container": container_info
    }


@app.post("/start")
def start_container(config: RedroidConfig = None):
    """Start or create Redroid container."""
    if not is_docker_installed():
        raise HTTPException(status_code=500, detail="Docker is not installed")

    config = config or RedroidConfig()

    if container_exists():
        # Start existing container
        stdout, stderr, code = run_cmd([
            "docker", "start", REDROID_CONTAINER
        ])
        if code != 0:
            raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")
    else:
        # Create and run new container
        cmd = [
            "docker", "run", "-d",
            "--name", REDROID_CONTAINER,
            "--privileged",
            "-p", f"{ADB_PORT}:5555",
            "--memory", config.memory,
            "--cpus", str(config.cpus),
        ]

        # GPU support
        if config.gpu:
            cmd.extend(["--device", "/dev/dri"])

        # Required for Android
        cmd.extend([
            "-v", "/dev/binderfs:/dev/binderfs",
            config.image
        ])

        stdout, stderr, code = run_cmd(cmd, timeout=300)
        if code != 0:
            raise HTTPException(status_code=500, detail=f"Failed to create container: {stderr}")

    # Connect ADB
    run_cmd(["adb", "connect", f"localhost:{ADB_PORT}"], check=False)

    return {"status": "started"}


@app.post("/stop")
def stop_container():
    """Stop Redroid container."""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container does not exist")

    stdout, stderr, code = run_cmd([
        "docker", "stop", REDROID_CONTAINER
    ])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")

    return {"status": "stopped"}


@app.post("/restart")
def restart_container():
    """Restart Redroid container."""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container does not exist")

    stdout, stderr, code = run_cmd([
        "docker", "restart", REDROID_CONTAINER
    ])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")

    # Reconnect ADB
    run_cmd(["adb", "connect", f"localhost:{ADB_PORT}"], check=False)

    return {"status": "restarted"}


@app.delete("/container")
def remove_container():
    """Remove Redroid container."""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container does not exist")

    # Stop if running
    if is_container_running():
        run_cmd(["docker", "stop", REDROID_CONTAINER])

    stdout, stderr, code = run_cmd([
        "docker", "rm", REDROID_CONTAINER
    ])

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to remove: {stderr}")

    return {"status": "removed"}


@app.get("/adb/devices")
def adb_devices():
    """List ADB devices."""
    stdout, stderr, code = run_cmd(["adb", "devices", "-l"])

    devices = []
    if code == 0:
        for line in stdout.strip().split('\n')[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    devices.append({
                        "device": parts[0],
                        "state": parts[1],
                        "info": " ".join(parts[2:]) if len(parts) > 2 else ""
                    })

    return {"devices": devices}


@app.post("/adb/connect")
def adb_connect():
    """Connect ADB to Redroid container."""
    stdout, stderr, code = run_cmd([
        "adb", "connect", f"localhost:{ADB_PORT}"
    ])

    return {
        "status": "connected" if "connected" in stdout.lower() else "failed",
        "output": stdout.strip()
    }


@app.post("/adb/disconnect")
def adb_disconnect():
    """Disconnect ADB from Redroid container."""
    stdout, stderr, code = run_cmd([
        "adb", "disconnect", f"localhost:{ADB_PORT}"
    ])

    return {"status": "disconnected", "output": stdout.strip()}


@app.post("/adb/shell")
def adb_shell(command: str):
    """Execute ADB shell command."""
    stdout, stderr, code = run_cmd([
        "adb", "-s", f"localhost:{ADB_PORT}", "shell", command
    ], timeout=30)

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": code
    }


@app.get("/adb/packages")
def list_packages():
    """List installed Android packages."""
    stdout, stderr, code = run_cmd([
        "adb", "-s", f"localhost:{ADB_PORT}", "shell", "pm", "list", "packages"
    ])

    packages = []
    if code == 0:
        for line in stdout.strip().split('\n'):
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())

    return {"packages": sorted(packages)}


@app.post("/adb/install")
def install_apk(apk_path: str):
    """Install APK via ADB."""
    if not os.path.exists(apk_path):
        raise HTTPException(status_code=404, detail="APK file not found")

    stdout, stderr, code = run_cmd([
        "adb", "-s", f"localhost:{ADB_PORT}", "install", apk_path
    ], timeout=120)

    if code != 0 or "failure" in stdout.lower():
        raise HTTPException(status_code=500, detail=f"Install failed: {stdout} {stderr}")

    return {"status": "installed", "output": stdout}


@app.get("/logs")
def get_logs(lines: int = 50):
    """Get container logs."""
    stdout, stderr, code = run_cmd([
        "docker", "logs", "--tail", str(lines), REDROID_CONTAINER
    ])

    return {"logs": (stdout + stderr).split('\n')}


@app.get("/images")
def list_images():
    """List available Redroid Docker images."""
    available = [
        {"tag": "redroid/redroid:14.0.0-latest", "android": "14", "api": 34},
        {"tag": "redroid/redroid:13.0.0-latest", "android": "13", "api": 33},
        {"tag": "redroid/redroid:12.0.0-latest", "android": "12", "api": 31},
        {"tag": "redroid/redroid:11.0.0-latest", "android": "11", "api": 30},
        {"tag": "redroid/redroid:10.0.0-latest", "android": "10", "api": 29},
        {"tag": "redroid/redroid:9.0.0-latest", "android": "9", "api": 28},
    ]

    # Check which are pulled locally
    stdout, _, _ = run_cmd(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    local_images = stdout.strip().split('\n') if stdout else []

    for img in available:
        img["pulled"] = img["tag"] in local_images

    return {"images": available}


@app.post("/images/pull/{tag:path}")
def pull_image(tag: str):
    """Pull a Redroid Docker image."""
    stdout, stderr, code = run_cmd([
        "docker", "pull", tag
    ], timeout=600)

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Pull failed: {stderr}")

    return {"status": "pulled", "tag": tag}
