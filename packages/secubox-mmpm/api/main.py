"""SecuBox MMPM API - MagicMirror Package Manager."""
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import subprocess
import json
import os
import urllib.request

app = FastAPI(title="SecuBox MMPM API", version="1.0.0")

MMPM_DB = "/var/lib/secubox/mmpm/modules.json"
MM_MODULES_DIR = "/opt/MagicMirror/modules"
MM_3RD_PARTY_URL = "https://raw.githubusercontent.com/MagicMirrorOrg/MagicMirror/master/modules/default/defaultmodules.js"


class ModuleInstall(BaseModel):
    name: str
    repo_url: str | None = None


def run_cmd(cmd: list, check: bool = True) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def load_module_db() -> list:
    """Load module database from cache."""
    if os.path.exists(MMPM_DB):
        try:
            with open(MMPM_DB, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_module_db(modules: list):
    """Save module database to cache."""
    os.makedirs(os.path.dirname(MMPM_DB), exist_ok=True)
    with open(MMPM_DB, 'w') as f:
        json.dump(modules, f, indent=2)


def get_installed_modules() -> list:
    """List installed third-party modules."""
    modules = []
    if not os.path.exists(MM_MODULES_DIR):
        return modules

    for entry in os.listdir(MM_MODULES_DIR):
        path = os.path.join(MM_MODULES_DIR, entry)
        if os.path.isdir(path) and entry not in ["default", "node_modules"]:
            module_info = {"name": entry, "path": path}

            # Check for package.json
            pkg_json = os.path.join(path, "package.json")
            if os.path.exists(pkg_json):
                try:
                    with open(pkg_json, 'r') as f:
                        pkg = json.load(f)
                        module_info["version"] = pkg.get("version", "unknown")
                        module_info["description"] = pkg.get("description", "")
                except Exception:
                    pass

            # Check for git repo
            git_dir = os.path.join(path, ".git")
            module_info["is_git"] = os.path.isdir(git_dir)

            modules.append(module_info)

    return modules


def fetch_module_registry() -> list:
    """Fetch list of available modules from MMPM wiki/registry."""
    # Popular MagicMirror modules (curated list)
    modules = [
        {"name": "MMM-CalendarExt2", "author": "MMM-CalendarExt2", "description": "Advanced calendar with events", "category": "calendar"},
        {"name": "MMM-SystemStats", "author": "BenRoe", "description": "System CPU, RAM, disk usage", "category": "system"},
        {"name": "MMM-Remote-Control", "author": "Jopyth", "description": "Remote control interface", "category": "utility"},
        {"name": "MMM-Wallpaper", "author": "kolbyjack", "description": "Dynamic wallpaper backgrounds", "category": "visual"},
        {"name": "MMM-cryptocurrency", "author": "matteodanelli", "description": "Cryptocurrency prices", "category": "finance"},
        {"name": "MMM-PIR-Sensor", "author": "paviro", "description": "PIR motion sensor control", "category": "hardware"},
        {"name": "MMM-Spotify", "author": "skuethe", "description": "Spotify now playing", "category": "music"},
        {"name": "MMM-GoogleMapsTraffic", "author": "vicmora", "description": "Google Maps traffic", "category": "travel"},
        {"name": "MMM-Todoist", "author": "cbroober", "description": "Todoist task list", "category": "productivity"},
        {"name": "MMM-GoogleFit", "author": "amcolash", "description": "Google Fit stats", "category": "health"},
        {"name": "MMM-NowPlayingOnSpotify", "author": "raywo", "description": "Spotify widget", "category": "music"},
        {"name": "MMM-NetworkScanner", "author": "ianperrin", "description": "Network device scanner", "category": "network"},
        {"name": "MMM-Globe", "author": "LukeSkyworker", "description": "Interactive 3D globe", "category": "visual"},
        {"name": "MMM-Facial-Recognition", "author": "paviro", "description": "Face recognition profiles", "category": "hardware"},
        {"name": "MMM-Assistant", "author": "bugsounet", "description": "Google Assistant", "category": "voice"},
        {"name": "MMM-HomeAssistant", "author": "wonderslug", "description": "Home Assistant sensors", "category": "smarthome"},
        {"name": "MMM-DarkSkyForecast", "author": "jclarke0000", "description": "Dark Sky weather", "category": "weather"},
        {"name": "MMM-OpenWeatherForecast", "author": "jclarke0000", "description": "OpenWeather forecast", "category": "weather"},
        {"name": "MMM-EmbPython", "author": "nissenm89", "description": "Embed Python scripts", "category": "developer"},
        {"name": "MMM-MQTT", "author": "ottopaulsen", "description": "MQTT data display", "category": "smarthome"},
    ]
    return modules


@app.get("/health")
def health():
    return {"status": "ok", "service": "mmpm"}


@app.get("/status")
def get_status():
    """Get MMPM status and overview."""
    installed = get_installed_modules()
    db = load_module_db()

    return {
        "installed_count": len(installed),
        "available_count": len(db) if db else 20,  # Fallback count
        "mm_modules_dir": MM_MODULES_DIR,
        "mm_installed": os.path.exists("/opt/MagicMirror")
    }


@app.get("/modules/installed")
def list_installed():
    """List installed third-party modules."""
    return {"modules": get_installed_modules()}


@app.get("/modules/available")
def list_available(category: str = None, search: str = None):
    """List available modules from registry."""
    modules = load_module_db()
    if not modules:
        modules = fetch_module_registry()
        save_module_db(modules)

    if category:
        modules = [m for m in modules if m.get("category") == category]

    if search:
        search_lower = search.lower()
        modules = [m for m in modules if
                   search_lower in m.get("name", "").lower() or
                   search_lower in m.get("description", "").lower()]

    return {"modules": modules}


@app.get("/modules/categories")
def list_categories():
    """List available module categories."""
    modules = load_module_db()
    if not modules:
        modules = fetch_module_registry()

    categories = set(m.get("category", "other") for m in modules)
    return {"categories": sorted(categories)}


@app.post("/modules/refresh")
def refresh_database():
    """Refresh the module database from registry."""
    modules = fetch_module_registry()
    save_module_db(modules)
    return {"status": "refreshed", "count": len(modules)}


@app.post("/modules/install")
def install_module(mod: ModuleInstall):
    """Install a module from GitHub."""
    if not mod.name.startswith("MMM-"):
        raise HTTPException(status_code=400, detail="Module name must start with MMM-")

    module_path = f"{MM_MODULES_DIR}/{mod.name}"

    if os.path.exists(module_path):
        raise HTTPException(status_code=409, detail="Module already installed")

    # Determine repo URL
    repo_url = mod.repo_url
    if not repo_url:
        # Try common GitHub patterns
        repo_url = f"https://github.com/MichMich/{mod.name}.git"

    # Clone the repository
    stdout, stderr, code = run_cmd(
        ["git", "clone", "--depth", "1", repo_url, module_path]
    )

    if code != 0:
        # Try alternative organizations
        for org in ["MagicMirrorOrg", "bugsounet", "CFenner", "jclarke0000"]:
            alt_url = f"https://github.com/{org}/{mod.name}.git"
            stdout, stderr, code = run_cmd(
                ["git", "clone", "--depth", "1", alt_url, module_path]
            )
            if code == 0:
                break

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to clone: {stderr}")

    # Run npm install if package.json exists
    if os.path.exists(f"{module_path}/package.json"):
        run_cmd(["npm", "install", "--prefix", module_path])

    return {"status": "installed", "module": mod.name, "path": module_path}


@app.delete("/modules/{module_name}")
def uninstall_module(module_name: str):
    """Uninstall a module."""
    module_path = f"{MM_MODULES_DIR}/{module_name}"

    if not os.path.exists(module_path):
        raise HTTPException(status_code=404, detail="Module not found")

    if module_name in ["default", "node_modules"]:
        raise HTTPException(status_code=400, detail="Cannot remove system directories")

    import shutil
    shutil.rmtree(module_path)

    return {"status": "uninstalled", "module": module_name}


@app.post("/modules/{module_name}/update")
def update_module(module_name: str):
    """Update an installed module via git pull."""
    module_path = f"{MM_MODULES_DIR}/{module_name}"

    if not os.path.exists(module_path):
        raise HTTPException(status_code=404, detail="Module not found")

    git_dir = f"{module_path}/.git"
    if not os.path.isdir(git_dir):
        raise HTTPException(status_code=400, detail="Module is not a git repository")

    # Git pull
    stdout, stderr, code = run_cmd(
        ["git", "-C", module_path, "pull", "--ff-only"]
    )

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Git pull failed: {stderr}")

    # Re-run npm install if package.json exists
    if os.path.exists(f"{module_path}/package.json"):
        run_cmd(["npm", "install", "--prefix", module_path])

    return {"status": "updated", "module": module_name, "output": stdout}


@app.get("/modules/{module_name}")
def get_module_info(module_name: str):
    """Get detailed info about an installed module."""
    module_path = f"{MM_MODULES_DIR}/{module_name}"

    if not os.path.exists(module_path):
        raise HTTPException(status_code=404, detail="Module not found")

    info = {"name": module_name, "path": module_path}

    # Read package.json
    pkg_json = f"{module_path}/package.json"
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, 'r') as f:
                pkg = json.load(f)
                info.update({
                    "version": pkg.get("version"),
                    "description": pkg.get("description"),
                    "author": pkg.get("author"),
                    "homepage": pkg.get("homepage"),
                    "dependencies": list(pkg.get("dependencies", {}).keys())
                })
        except Exception:
            pass

    # Check README
    for readme in ["README.md", "readme.md", "README.txt", "README"]:
        readme_path = f"{module_path}/{readme}"
        if os.path.exists(readme_path):
            info["has_readme"] = True
            break

    # Check git status
    git_dir = f"{module_path}/.git"
    if os.path.isdir(git_dir):
        info["is_git"] = True
        stdout, _, _ = run_cmd(["git", "-C", module_path, "log", "-1", "--format=%h %s"])
        info["last_commit"] = stdout.strip() if stdout else None

    return info


@app.get("/search")
def search_modules(q: str = Query(..., min_length=2)):
    """Search for modules by name or description."""
    modules = load_module_db()
    if not modules:
        modules = fetch_module_registry()

    q_lower = q.lower()
    results = []

    for m in modules:
        score = 0
        name = m.get("name", "").lower()
        desc = m.get("description", "").lower()

        if q_lower in name:
            score += 10
            if name.startswith(q_lower):
                score += 5

        if q_lower in desc:
            score += 3

        if score > 0:
            results.append({**m, "_score": score})

    results.sort(key=lambda x: x["_score"], reverse=True)

    # Remove score from output
    for r in results:
        del r["_score"]

    return {"query": q, "results": results[:20]}
