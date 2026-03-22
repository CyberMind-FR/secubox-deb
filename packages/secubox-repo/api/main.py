#!/usr/bin/env python3
"""
SecuBox Repo API — APT Repository Management
"""
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import json
import os
import shutil
import tempfile

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt, get_current_user
except ImportError:
    # Development fallback
    async def require_jwt():
        return {"sub": "admin"}
    get_current_user = require_jwt

app = FastAPI(
    title="SecuBox Repo API",
    description="APT Repository Management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

REPOCTL = "/usr/sbin/repoctl"
REPO_BASE = os.environ.get("REPO_BASE", "/var/lib/secubox-repo")
REPO_OUT = os.environ.get("REPO_OUT", "/var/www/apt.secubox.in")
UPLOAD_DIR = "/tmp/repo-uploads"

# ══════════════════════════════════════════════════════════════════
# Models
# ══════════════════════════════════════════════════════════════════

class Package(BaseModel):
    package: str
    version: str
    arch: str

class AddPackageRequest(BaseModel):
    distribution: str = "bookworm"

class RemovePackageRequest(BaseModel):
    distribution: str
    package: str

class SyncRequest(BaseModel):
    destination: str

# ══════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════

def run_repoctl(*args, parse_json=False):
    """Run repoctl command and return output."""
    cmd = [REPOCTL] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        if parse_json and result.returncode == 0:
            return json.loads(result.stdout)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid JSON output", "raw": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

def count_packages(dist: str = "bookworm") -> int:
    """Count packages in a distribution."""
    pool_path = os.path.join(REPO_OUT, "pool", "main")
    if not os.path.exists(pool_path):
        return 0
    count = 0
    for root, dirs, files in os.walk(pool_path):
        count += sum(1 for f in files if f.endswith('.deb'))
    return count

def list_distributions() -> List[str]:
    """List available distributions."""
    dists_path = os.path.join(REPO_OUT, "dists")
    if not os.path.exists(dists_path):
        return []
    return [d for d in os.listdir(dists_path) if os.path.isdir(os.path.join(dists_path, d))]

# ══════════════════════════════════════════════════════════════════
# Public Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/status")
async def get_status():
    """Get repository status."""
    return run_repoctl("status", "--json", parse_json=True)

@app.get("/components")
async def get_components():
    """Get required components status."""
    return run_repoctl("components", parse_json=True)

@app.get("/access")
async def get_access():
    """Get access information."""
    return run_repoctl("access", parse_json=True)

@app.get("/distributions")
async def get_distributions():
    """List available distributions."""
    return {"distributions": list_distributions()}

@app.get("/packages/{distribution}")
async def list_packages(distribution: str = "bookworm"):
    """List packages in a distribution."""
    result = run_repoctl("list", distribution, "--json", parse_json=True)
    if isinstance(result, list):
        return {"distribution": distribution, "packages": result, "count": len(result)}
    return result

@app.get("/stats")
async def get_stats():
    """Get repository statistics."""
    dists = list_distributions()
    stats = {
        "total_packages": 0,
        "distributions": {}
    }
    for dist in dists:
        count = count_packages(dist)
        stats["distributions"][dist] = count
        stats["total_packages"] += count
    return stats

# ══════════════════════════════════════════════════════════════════
# Protected Endpoints (require JWT)
# ══════════════════════════════════════════════════════════════════

@app.post("/init")
async def init_repository(user: dict = Depends(require_jwt)):
    """Initialize the repository."""
    return run_repoctl("init")

@app.post("/gpg/setup")
async def setup_gpg(user: dict = Depends(require_jwt)):
    """Generate GPG signing key."""
    return run_repoctl("gpg-setup")

@app.get("/gpg/fingerprint")
async def get_gpg_fingerprint(user: dict = Depends(require_jwt)):
    """Get GPG key fingerprint."""
    return run_repoctl("gpg-export", ".", "fingerprint")

@app.post("/upload")
async def upload_package(
    file: UploadFile = File(...),
    distribution: str = "bookworm",
    user: dict = Depends(require_jwt)
):
    """Upload and add a .deb package."""
    if not file.filename.endswith('.deb'):
        raise HTTPException(status_code=400, detail="Only .deb files allowed")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    try:
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        result = run_repoctl("add", distribution, file_path)
        return {
            "filename": file.filename,
            "distribution": distribution,
            **result
        }
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@app.post("/add")
async def add_packages(
    request: AddPackageRequest,
    packages: List[str],
    user: dict = Depends(require_jwt)
):
    """Add packages from local paths."""
    args = ["add", request.distribution] + packages
    return run_repoctl(*args)

@app.post("/remove")
async def remove_package(
    request: RemovePackageRequest,
    user: dict = Depends(require_jwt)
):
    """Remove a package from the repository."""
    return run_repoctl("remove", request.distribution, request.package)

@app.post("/sync")
async def sync_repository(
    request: SyncRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Sync repository to remote server."""
    # Run sync in background for large repos
    def do_sync():
        run_repoctl("sync", request.destination)

    background_tasks.add_task(do_sync)
    return {"status": "sync_started", "destination": request.destination}

# ══════════════════════════════════════════════════════════════════
# Health Check
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "secubox-repo"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
