"""SecuBox MagicMirror API - Smart display platform management."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
import re

app = FastAPI(title="SecuBox MagicMirror API", version="1.0.0")

MM_DIR = "/opt/MagicMirror"
CONFIG_FILE = f"{MM_DIR}/config/config.js"
MODULES_DIR = f"{MM_DIR}/modules"
SERVICE_NAME = "magicmirror"


class ModuleConfig(BaseModel):
    module: str
    position: str = "top_right"
    config: dict = {}


class DisplayConfig(BaseModel):
    port: int = 8080
    address: str = "0.0.0.0"
    ipWhitelist: list = []
    language: str = "en"
    timeFormat: int = 24
    units: str = "metric"


def run_cmd(cmd: list, check: bool = True) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def is_service_running() -> bool:
    """Check if MagicMirror service is running."""
    _, _, code = run_cmd(["systemctl", "is-active", "--quiet", SERVICE_NAME], check=False)
    return code == 0


def parse_config_js() -> dict:
    """Parse MagicMirror config.js to extract configuration."""
    if not os.path.exists(CONFIG_FILE):
        return {}

    try:
        with open(CONFIG_FILE, 'r') as f:
            content = f.read()

        # Extract modules array using regex (simplified parsing)
        modules = []
        module_pattern = r'\{\s*module:\s*["\']([^"\']+)["\']'
        for match in re.finditer(module_pattern, content):
            modules.append(match.group(1))

        # Extract basic settings
        port_match = re.search(r'port:\s*(\d+)', content)
        lang_match = re.search(r'language:\s*["\'](\w+)["\']', content)

        return {
            "modules": modules,
            "port": int(port_match.group(1)) if port_match else 8080,
            "language": lang_match.group(1) if lang_match else "en"
        }
    except Exception:
        return {}


def list_installed_modules() -> list:
    """List installed MagicMirror modules."""
    modules = []
    default_modules = ["alert", "calendar", "clock", "compliments", "currentweather",
                       "helloworld", "newsfeed", "weatherforecast", "updatenotification"]

    # Add default modules
    for mod in default_modules:
        modules.append({"name": mod, "type": "default", "path": f"{MODULES_DIR}/default/{mod}"})

    # Add third-party modules
    if os.path.exists(MODULES_DIR):
        for entry in os.listdir(MODULES_DIR):
            path = os.path.join(MODULES_DIR, entry)
            if os.path.isdir(path) and entry not in ["default", "node_modules"]:
                modules.append({"name": entry, "type": "third-party", "path": path})

    return modules


def list_available_modules() -> list:
    """Return list of popular MagicMirror modules for installation."""
    return [
        {"name": "MMM-GoogleCalendar", "description": "Google Calendar integration"},
        {"name": "MMM-Spotify", "description": "Spotify now playing widget"},
        {"name": "MMM-SystemStats", "description": "System CPU/RAM/disk stats"},
        {"name": "MMM-Network-Signal", "description": "Network signal strength"},
        {"name": "MMM-Wallpaper", "description": "Dynamic wallpaper backgrounds"},
        {"name": "MMM-cryptocurrency", "description": "Cryptocurrency prices"},
        {"name": "MMM-PIR-Sensor", "description": "Motion sensor screen control"},
        {"name": "MMM-homeassistant-sensors", "description": "Home Assistant integration"},
        {"name": "MMM-Facial-Recognition", "description": "Face recognition profiles"},
        {"name": "MMM-voice-assistant", "description": "Voice control integration"},
    ]


@app.get("/health")
def health():
    return {"status": "ok", "service": "magicmirror"}


@app.get("/status")
def get_status():
    """Get MagicMirror service status and configuration."""
    running = is_service_running()
    installed = os.path.exists(MM_DIR)
    config = parse_config_js() if installed else {}

    return {
        "installed": installed,
        "running": running,
        "mm_dir": MM_DIR,
        "config": config,
        "module_count": len(config.get("modules", []))
    }


@app.post("/start")
def start_service():
    """Start MagicMirror service."""
    stdout, stderr, code = run_cmd(["systemctl", "start", SERVICE_NAME])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")
    return {"status": "started"}


@app.post("/stop")
def stop_service():
    """Stop MagicMirror service."""
    stdout, stderr, code = run_cmd(["systemctl", "stop", SERVICE_NAME])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")
    return {"status": "stopped"}


@app.post("/restart")
def restart_service():
    """Restart MagicMirror service."""
    stdout, stderr, code = run_cmd(["systemctl", "restart", SERVICE_NAME])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")
    return {"status": "restarted"}


@app.get("/modules")
def get_modules():
    """List all installed modules."""
    return {"modules": list_installed_modules()}


@app.get("/modules/available")
def get_available_modules():
    """List popular modules available for installation."""
    return {"modules": list_available_modules()}


@app.post("/modules/install/{module_name}")
def install_module(module_name: str):
    """Install a third-party MagicMirror module from GitHub."""
    if not module_name.startswith("MMM-"):
        raise HTTPException(status_code=400, detail="Module name must start with MMM-")

    module_path = f"{MODULES_DIR}/{module_name}"
    if os.path.exists(module_path):
        raise HTTPException(status_code=409, detail="Module already installed")

    # Clone from GitHub (most MM modules follow this pattern)
    github_url = f"https://github.com/MichMich/{module_name}.git"
    stdout, stderr, code = run_cmd(
        ["git", "clone", "--depth", "1", github_url, module_path],
        check=False
    )

    if code != 0:
        # Try alternative org patterns
        for org in ["MagicMirrorOrg", "bugsounet"]:
            github_url = f"https://github.com/{org}/{module_name}.git"
            stdout, stderr, code = run_cmd(
                ["git", "clone", "--depth", "1", github_url, module_path],
                check=False
            )
            if code == 0:
                break

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to clone module: {stderr}")

    # Run npm install if package.json exists
    if os.path.exists(f"{module_path}/package.json"):
        run_cmd(["npm", "install", "--prefix", module_path], check=False)

    return {"status": "installed", "module": module_name, "path": module_path}


@app.delete("/modules/{module_name}")
def uninstall_module(module_name: str):
    """Uninstall a third-party module."""
    module_path = f"{MODULES_DIR}/{module_name}"

    if not os.path.exists(module_path):
        raise HTTPException(status_code=404, detail="Module not found")

    if module_name in ["default", "node_modules"]:
        raise HTTPException(status_code=400, detail="Cannot remove system directories")

    import shutil
    shutil.rmtree(module_path)

    return {"status": "uninstalled", "module": module_name}


@app.get("/config")
def get_config():
    """Get current MagicMirror configuration."""
    if not os.path.exists(CONFIG_FILE):
        raise HTTPException(status_code=404, detail="Config file not found")

    with open(CONFIG_FILE, 'r') as f:
        content = f.read()

    return {"config_file": CONFIG_FILE, "content": content}


@app.get("/logs")
def get_logs(lines: int = 50):
    """Get recent MagicMirror logs."""
    stdout, stderr, code = run_cmd(
        ["journalctl", "-u", SERVICE_NAME, "-n", str(lines), "--no-pager"]
    )
    return {"logs": stdout.split('\n') if stdout else []}


@app.get("/display")
def get_display_info():
    """Get display/screen information."""
    # Check for display server
    display_info = {
        "DISPLAY": os.environ.get("DISPLAY", ""),
        "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY", "")
    }

    # Get screen resolution if xrandr available
    stdout, _, code = run_cmd(["xrandr", "--current"], check=False)
    if code == 0:
        for line in stdout.split('\n'):
            if '*' in line:  # Current resolution marked with *
                parts = line.split()
                if parts:
                    display_info["resolution"] = parts[0]
                    break

    return display_info


@app.post("/display/brightness/{level}")
def set_brightness(level: int):
    """Set display brightness (0-100)."""
    if not 0 <= level <= 100:
        raise HTTPException(status_code=400, detail="Brightness must be 0-100")

    # Try xrandr brightness
    brightness = level / 100.0
    stdout, stderr, code = run_cmd(
        ["xrandr", "--output", "HDMI-1", "--brightness", str(brightness)],
        check=False
    )

    if code != 0:
        # Try other common output names
        for output in ["HDMI-0", "DP-1", "eDP-1", "VGA-1"]:
            _, _, code = run_cmd(
                ["xrandr", "--output", output, "--brightness", str(brightness)],
                check=False
            )
            if code == 0:
                break

    return {"brightness": level}


@app.post("/display/power/{state}")
def set_display_power(state: str):
    """Turn display on or off."""
    if state not in ["on", "off"]:
        raise HTTPException(status_code=400, detail="State must be 'on' or 'off'")

    if state == "off":
        run_cmd(["xset", "dpms", "force", "off"], check=False)
    else:
        run_cmd(["xset", "dpms", "force", "on"], check=False)
        run_cmd(["xset", "s", "reset"], check=False)

    return {"display": state}
