#!/usr/bin/env python3
"""SecuBox Repo API - APT Repository Management with Enhanced Monitoring"""
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
import subprocess
import json
import os
import shutil
import threading
import time
import asyncio
import hashlib
import hmac
import httpx
from datetime import datetime, timedelta
from pathlib import Path

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt, get_current_user
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}
    get_current_user = require_jwt

app = FastAPI(
    title="SecuBox Repo API",
    description="APT Repository Management",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None
)

# Configuration
REPOCTL = "/usr/sbin/repoctl"
REPO_BASE = os.environ.get("REPO_BASE", "/var/lib/secubox-repo")
REPO_OUT = os.environ.get("REPO_OUT", "/var/www/apt.secubox.in")
UPLOAD_DIR = "/tmp/repo-uploads"
DATA_DIR = Path("/var/lib/secubox/repo")
DATA_DIR.mkdir(parents=True, exist_ok=True)

HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"


class StatsCache:
    """Thread-safe stats cache with TTL."""

    def __init__(self, ttl_seconds: int = 60):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=60)


# Pydantic Models
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


class ScanLocalRequest(BaseModel):
    paths: List[str] = Field(
        default=["/var/cache/apt/archives", "/tmp/debs"],
        description="Directories to scan for .deb packages"
    )
    distribution: str = "bookworm"
    recursive: bool = True
    dry_run: bool = False


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["package_added", "package_removed", "sync_complete"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_monitoring_task: Optional[asyncio.Task] = None


def _format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _load_json(filepath: Path, default=None):
    """Load JSON file safely."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save_json(filepath: Path, data):
    """Save JSON file safely."""
    filepath.write_text(json.dumps(data, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-1000:]
    _save_json(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load_json(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save_json(WEBHOOKS_FILE, webhooks)


def _record_event(event: str, details: Optional[Dict] = None):
    """Record an event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "details": details or {}
    }
    history.append(entry)
    _save_history(history)


async def _send_webhook(url: str, payload: Dict[str, Any], secret: Optional[str] = None):
    """Send webhook notification."""
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={signature}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def _notify_webhooks(event: str, data: Dict[str, Any]):
    """Send notifications to all webhooks for event."""
    webhooks = _load_webhooks()
    for webhook in webhooks:
        if webhook.get("enabled", True) and event in webhook.get("events", []):
            await _send_webhook(
                webhook["url"],
                {"event": event, "data": data, "timestamp": datetime.now().isoformat()},
                webhook.get("secret")
            )


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


def get_repo_size() -> Dict[str, Any]:
    """Get repository size statistics."""
    total_bytes = 0
    file_count = 0
    by_arch: Dict[str, int] = {}

    pool_path = Path(REPO_OUT) / "pool"
    if pool_path.exists():
        for f in pool_path.rglob("*.deb"):
            size = f.stat().st_size
            total_bytes += size
            file_count += 1

            # Extract arch from filename
            parts = f.name.rsplit("_", 1)
            if len(parts) == 2:
                arch = parts[1].replace(".deb", "")
                by_arch[arch] = by_arch.get(arch, 0) + size

    return {
        "total_bytes": total_bytes,
        "total_human": _format_bytes(total_bytes),
        "file_count": file_count,
        "by_arch": {arch: _format_bytes(size) for arch, size in by_arch.items()}
    }


def get_recent_packages(limit: int = 10) -> List[Dict[str, Any]]:
    """Get recently added packages."""
    pool_path = Path(REPO_OUT) / "pool"
    if not pool_path.exists():
        return []

    packages = []
    for f in pool_path.rglob("*.deb"):
        stat = f.stat()
        packages.append({
            "name": f.name,
            "path": str(f.relative_to(REPO_OUT)),
            "size": stat.st_size,
            "size_human": _format_bytes(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })

    packages.sort(key=lambda x: x["modified"], reverse=True)
    return packages[:limit]


async def _update_stats():
    """Background task to update repository statistics."""
    while True:
        try:
            dists = list_distributions()
            size_info = get_repo_size()

            # Build distributions dict with counts
            dist_counts = {}
            for dist in dists:
                result = run_repoctl("list", dist, "--json", parse_json=True)
                if isinstance(result, list):
                    dist_counts[dist] = len(result)
                else:
                    dist_counts[dist] = 0

            stats = {
                "distributions": dist_counts,
                "total_packages": size_info["file_count"],
                "size": size_info,
                "updated": datetime.now().isoformat()
            }
            _save_json(STATS_FILE, stats)
            stats_cache.set("repo_stats", stats)
        except Exception:
            pass

        await asyncio.sleep(300)  # Update every 5 minutes


@app.on_event("startup")
async def startup():
    """Start background stats update."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_update_stats())


@app.on_event("shutdown")
async def shutdown():
    """Stop background tasks."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public Endpoints
@app.get("/status")
async def get_status():
    """Get repository status."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    result = run_repoctl("status", "--json", parse_json=True)
    if isinstance(result, dict) and "success" not in result:
        result["timestamp"] = datetime.now().isoformat()
        stats_cache.set("status", result)

    return result


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "secubox-repo",
        "version": "2.0.0"
    }


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
    return {
        "distributions": list_distributions(),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/packages/{distribution}")
async def list_packages_dist(distribution: str = "bookworm"):
    """List packages in a distribution."""
    cached = stats_cache.get(f"packages_{distribution}")
    if cached:
        return cached

    result = run_repoctl("list", distribution, "--json", parse_json=True)
    if isinstance(result, list):
        response = {
            "distribution": distribution,
            "packages": result,
            "count": len(result),
            "timestamp": datetime.now().isoformat()
        }
        stats_cache.set(f"packages_{distribution}", response)
        return response
    return result


@app.get("/packages")
async def list_all_packages():
    """List all packages across all distributions."""
    all_packages = []
    for dist in list_distributions():
        result = await list_packages_dist(dist)
        if isinstance(result, dict) and "packages" in result:
            for pkg in result["packages"]:
                pkg["distribution"] = dist
                all_packages.append(pkg)

    return {
        "packages": all_packages,
        "count": len(all_packages),
        "distributions": list_distributions()
    }


@app.get("/stats")
async def get_stats():
    """Get repository statistics."""
    cached = stats_cache.get("repo_stats")
    if cached:
        return cached

    dists = list_distributions()
    size_info = get_repo_size()

    stats = {
        "total_packages": size_info["file_count"],
        "distributions": {},
        "size": size_info,
        "timestamp": datetime.now().isoformat()
    }

    for dist in dists:
        result = run_repoctl("list", dist, "--json", parse_json=True)
        if isinstance(result, list):
            stats["distributions"][dist] = len(result)
        else:
            stats["distributions"][dist] = 0

    stats_cache.set("repo_stats", stats)
    return stats


@app.get("/recent")
async def get_recent():
    """Get recently added packages."""
    return {
        "packages": get_recent_packages(20),
        "timestamp": datetime.now().isoformat()
    }


# Protected Endpoints
@app.post("/init")
async def init_repository(user: dict = Depends(require_jwt)):
    """Initialize the repository."""
    result = run_repoctl("init")
    if result.get("success"):
        _record_event("repo_init", {"user": user.get("sub")})
        stats_cache.clear()
    return result


@app.post("/gpg/setup")
async def setup_gpg(user: dict = Depends(require_jwt)):
    """Generate GPG signing key."""
    result = run_repoctl("gpg-setup")
    if result.get("success"):
        _record_event("gpg_setup", {"user": user.get("sub")})
    return result


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

        file_size = os.path.getsize(file_path)
        result = run_repoctl("add", distribution, file_path)

        if result.get("success"):
            _record_event("package_added", {
                "filename": file.filename,
                "distribution": distribution,
                "size": file_size,
                "user": user.get("sub")
            })
            await _notify_webhooks("package_added", {
                "filename": file.filename,
                "distribution": distribution,
                "size": _format_bytes(file_size)
            })
            stats_cache.clear()

        return {
            "filename": file.filename,
            "distribution": distribution,
            "size": _format_bytes(file_size),
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
    result = run_repoctl(*args)

    if result.get("success"):
        _record_event("packages_added", {
            "distribution": request.distribution,
            "count": len(packages),
            "user": user.get("sub")
        })
        stats_cache.clear()

    return result


@app.post("/scan-local")
async def scan_local_packages(
    request: ScanLocalRequest = None,
    user: dict = Depends(require_jwt)
):
    """Scan local system directories for .deb packages and add them to the repository."""
    if request is None:
        request = ScanLocalRequest()

    found_packages: List[Dict[str, Any]] = []
    added_packages: List[str] = []
    failed_packages: List[Dict[str, str]] = []
    skipped_packages: List[str] = []

    # Scan each path for .deb files
    for scan_path in request.paths:
        path = Path(scan_path)
        if not path.exists():
            continue

        if request.recursive:
            deb_files = list(path.rglob("*.deb"))
        else:
            deb_files = list(path.glob("*.deb"))

        for deb_file in deb_files:
            try:
                stat = deb_file.stat()
                pkg_info = {
                    "path": str(deb_file),
                    "name": deb_file.name,
                    "size": stat.st_size,
                    "size_human": _format_bytes(stat.st_size),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
                found_packages.append(pkg_info)
            except Exception as e:
                failed_packages.append({"path": str(deb_file), "error": str(e)})

    if request.dry_run:
        return {
            "dry_run": True,
            "distribution": request.distribution,
            "paths_scanned": request.paths,
            "found_packages": found_packages,
            "total_found": len(found_packages),
            "total_size": _format_bytes(sum(p.get("size", 0) for p in found_packages)),
            "timestamp": datetime.now().isoformat()
        }

    # Add packages to repository
    for pkg in found_packages:
        try:
            result = run_repoctl("add", request.distribution, pkg["path"])
            output = result.get("output", "") or ""
            error = result.get("error", "") or ""
            combined = output + error

            # Check for success indicators (repoctl uses ANSI colored [OK] messages)
            if result.get("success") or "[OK]" in combined or "Added:" in combined:
                added_packages.append(pkg["name"])
            elif "already" in combined.lower() or "exists" in combined.lower():
                skipped_packages.append(pkg["name"])
            else:
                failed_packages.append({
                    "path": pkg["path"],
                    "error": combined.strip() or "Unknown error"
                })
        except Exception as e:
            failed_packages.append({"path": pkg["path"], "error": str(e)})

    # Record event and notify
    if added_packages:
        _record_event("scan_local", {
            "distribution": request.distribution,
            "added_count": len(added_packages),
            "skipped_count": len(skipped_packages),
            "failed_count": len(failed_packages),
            "paths": request.paths,
            "user": user.get("sub")
        })
        await _notify_webhooks("packages_added", {
            "source": "scan_local",
            "distribution": request.distribution,
            "count": len(added_packages),
            "packages": added_packages[:10]  # Limit webhook payload
        })
        stats_cache.clear()

    return {
        "success": len(failed_packages) == 0 or len(added_packages) > 0,
        "distribution": request.distribution,
        "paths_scanned": request.paths,
        "added": added_packages,
        "added_count": len(added_packages),
        "skipped": skipped_packages,
        "skipped_count": len(skipped_packages),
        "failed": failed_packages,
        "failed_count": len(failed_packages),
        "total_found": len(found_packages),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/scan-local/preview")
async def preview_scan_local(
    paths: str = "/var/cache/apt/archives",
    recursive: bool = True,
    user: dict = Depends(require_jwt)
):
    """Preview what packages would be imported from local paths without adding them."""
    path_list = [p.strip() for p in paths.split(",") if p.strip()]
    request = ScanLocalRequest(paths=path_list, recursive=recursive, dry_run=True)
    return await scan_local_packages(request, user)


@app.post("/remove")
async def remove_package(
    request: RemovePackageRequest,
    user: dict = Depends(require_jwt)
):
    """Remove a package from the repository."""
    result = run_repoctl("remove", request.distribution, request.package)

    if result.get("success"):
        _record_event("package_removed", {
            "distribution": request.distribution,
            "package": request.package,
            "user": user.get("sub")
        })
        await _notify_webhooks("package_removed", {
            "distribution": request.distribution,
            "package": request.package
        })
        stats_cache.clear()

    return result


@app.post("/sync")
async def sync_repository(
    request: SyncRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Sync repository to remote server."""
    _record_event("sync_started", {
        "destination": request.destination,
        "user": user.get("sub")
    })

    async def do_sync():
        result = run_repoctl("sync", request.destination)
        _record_event("sync_complete", {
            "destination": request.destination,
            "success": result.get("success", False)
        })
        await _notify_webhooks("sync_complete", {
            "destination": request.destination,
            "success": result.get("success", False)
        })

    background_tasks.add_task(do_sync)
    return {"status": "sync_started", "destination": request.destination}


@app.get("/history")
async def get_history(limit: int = 100, user: dict = Depends(require_jwt)):
    """Get repository event history."""
    history = _load_history()
    return {
        "events": history[-limit:],
        "total": len(history)
    }


@app.get("/webhooks")
async def list_webhooks(user: dict = Depends(require_jwt)):
    """List configured webhooks."""
    return {"webhooks": _load_webhooks()}


@app.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user: dict = Depends(require_jwt)):
    """Add a new webhook."""
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user: dict = Depends(require_jwt)):
    """Delete a webhook."""
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@app.get("/summary")
async def summary():
    """Get repository summary."""
    stats = await get_stats()
    recent = get_recent_packages(5)
    history = _load_history()

    # Handle distributions as either dict or list
    dists = stats.get("distributions", {})
    if isinstance(dists, dict):
        dist_names = list(dists.keys())
    else:
        dist_names = dists if isinstance(dists, list) else []

    return {
        "total_packages": stats.get("total_packages", 0),
        "distributions": dist_names,
        "size": stats.get("size", {}).get("total_human", "0 B"),
        "recent_packages": [p["name"] for p in recent],
        "recent_events": history[-5:],
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
