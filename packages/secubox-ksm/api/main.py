"""
SecuBox-Deb :: secubox-ksm
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Kernel Same-page Merging (KSM) management module.
Provides controls for KSM to optimize memory in VMs/containers.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-ksm", version="1.0.0", root_path="/api/v1/ksm")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("ksm")

# KSM sysfs paths
KSM_BASE = Path("/sys/kernel/mm/ksm")
KSM_RUN = KSM_BASE / "run"
KSM_PAGES_TO_SCAN = KSM_BASE / "pages_to_scan"
KSM_SLEEP_MILLISECS = KSM_BASE / "sleep_millisecs"
KSM_PAGES_SHARED = KSM_BASE / "pages_shared"
KSM_PAGES_SHARING = KSM_BASE / "pages_sharing"
KSM_PAGES_UNSHARED = KSM_BASE / "pages_unshared"
KSM_FULL_SCANS = KSM_BASE / "full_scans"
KSM_STABLE_NODE_CHAINS = KSM_BASE / "stable_node_chains"
KSM_STABLE_NODE_DUPS = KSM_BASE / "stable_node_dups"

# Configuration
CONFIG_FILE = Path("/etc/secubox/ksm.toml")
DATA_DIR = Path("/var/lib/secubox/ksm")

# Page size for memory calculations (typically 4KB)
PAGE_SIZE = 4096


class KSMConfig(BaseModel):
    """KSM configuration model."""
    pages_to_scan: int = Field(default=100, ge=1, le=10000)
    sleep_millisecs: int = Field(default=20, ge=10, le=1000)


def _read_sysfs(path: Path) -> Optional[int]:
    """Read an integer value from sysfs."""
    try:
        if path.exists():
            return int(path.read_text().strip())
    except (ValueError, IOError, PermissionError) as e:
        log.warning("Failed to read %s: %s", path, e)
    return None


def _write_sysfs(path: Path, value: int) -> bool:
    """Write an integer value to sysfs."""
    try:
        if path.exists():
            path.write_text(str(value))
            return True
    except (IOError, PermissionError) as e:
        log.error("Failed to write %s: %s", path, e)
    return False


def _ksm_available() -> bool:
    """Check if KSM is available on this system."""
    return KSM_BASE.exists() and KSM_RUN.exists()


def _get_ksm_status() -> Dict[str, Any]:
    """Get current KSM status."""
    if not _ksm_available():
        return {
            "available": False,
            "enabled": False,
            "error": "KSM not available on this system"
        }

    run_value = _read_sysfs(KSM_RUN)
    return {
        "available": True,
        "enabled": run_value == 1 if run_value is not None else False,
        "run_value": run_value
    }


def _get_ksm_stats() -> Dict[str, Any]:
    """Get KSM statistics."""
    if not _ksm_available():
        return {"error": "KSM not available"}

    pages_shared = _read_sysfs(KSM_PAGES_SHARED) or 0
    pages_sharing = _read_sysfs(KSM_PAGES_SHARING) or 0
    pages_unshared = _read_sysfs(KSM_PAGES_UNSHARED) or 0
    full_scans = _read_sysfs(KSM_FULL_SCANS) or 0

    # Calculate memory saved
    # pages_sharing - pages_shared = deduplicated pages
    # Memory saved = deduplicated pages * page_size
    if pages_sharing > 0:
        memory_saved_pages = pages_sharing - pages_shared
        memory_saved_bytes = memory_saved_pages * PAGE_SIZE
    else:
        memory_saved_pages = 0
        memory_saved_bytes = 0

    return {
        "pages_shared": pages_shared,
        "pages_sharing": pages_sharing,
        "pages_unshared": pages_unshared,
        "full_scans": full_scans,
        "memory_saved_bytes": memory_saved_bytes,
        "memory_saved_human": _format_bytes(memory_saved_bytes),
        "stable_node_chains": _read_sysfs(KSM_STABLE_NODE_CHAINS),
        "stable_node_dups": _read_sysfs(KSM_STABLE_NODE_DUPS),
        "timestamp": datetime.now().isoformat()
    }


def _get_ksm_config() -> Dict[str, Any]:
    """Get current KSM configuration."""
    if not _ksm_available():
        return {"error": "KSM not available"}

    return {
        "pages_to_scan": _read_sysfs(KSM_PAGES_TO_SCAN) or 100,
        "sleep_millisecs": _read_sysfs(KSM_SLEEP_MILLISECS) or 20,
        "timestamp": datetime.now().isoformat()
    }


def _format_bytes(size: float) -> str:
    """Format bytes to human readable size."""
    if size == 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# Health endpoint (public)
@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "ksm", "version": "1.0.0"}


# Status endpoint (public for dashboard)
@router.get("/status")
async def status():
    """Get KSM status."""
    result = _get_ksm_status()
    result["timestamp"] = datetime.now().isoformat()
    return result


# Stats endpoint (public for dashboard)
@router.get("/stats")
async def stats():
    """Get KSM statistics."""
    return _get_ksm_stats()


# Summary endpoint (public for dashboard widget)
@router.get("/summary")
async def summary():
    """Get KSM summary for dashboard widget."""
    status_info = _get_ksm_status()
    stats_info = _get_ksm_stats()

    return {
        "available": status_info.get("available", False),
        "enabled": status_info.get("enabled", False),
        "pages_shared": stats_info.get("pages_shared", 0),
        "pages_sharing": stats_info.get("pages_sharing", 0),
        "memory_saved": stats_info.get("memory_saved_human", "0 B"),
        "full_scans": stats_info.get("full_scans", 0),
        "timestamp": datetime.now().isoformat()
    }


# Protected endpoints
@router.post("/enable")
async def enable_ksm(user=Depends(require_jwt)):
    """Enable KSM."""
    if not _ksm_available():
        raise HTTPException(status_code=503, detail="KSM not available on this system")

    success = _write_sysfs(KSM_RUN, 1)
    if success:
        log.info("KSM enabled by %s", user.get("sub"))
        return {"success": True, "message": "KSM enabled"}
    else:
        raise HTTPException(status_code=500, detail="Failed to enable KSM")


@router.post("/disable")
async def disable_ksm(user=Depends(require_jwt)):
    """Disable KSM."""
    if not _ksm_available():
        raise HTTPException(status_code=503, detail="KSM not available on this system")

    success = _write_sysfs(KSM_RUN, 0)
    if success:
        log.info("KSM disabled by %s", user.get("sub"))
        return {"success": True, "message": "KSM disabled"}
    else:
        raise HTTPException(status_code=500, detail="Failed to disable KSM")


@router.get("/config")
async def get_config_endpoint(user=Depends(require_jwt)):
    """Get KSM configuration."""
    config = _get_ksm_config()

    # Also load any saved TOML config
    try:
        toml_config = get_config("ksm")
        if toml_config:
            config["saved_config"] = toml_config
    except Exception:
        pass

    return config


@router.post("/config")
async def update_config(config: KSMConfig, user=Depends(require_jwt)):
    """Update KSM configuration."""
    if not _ksm_available():
        raise HTTPException(status_code=503, detail="KSM not available on this system")

    errors = []

    # Update pages_to_scan
    if not _write_sysfs(KSM_PAGES_TO_SCAN, config.pages_to_scan):
        errors.append("Failed to set pages_to_scan")

    # Update sleep_millisecs
    if not _write_sysfs(KSM_SLEEP_MILLISECS, config.sleep_millisecs):
        errors.append("Failed to set sleep_millisecs")

    if errors:
        raise HTTPException(status_code=500, detail="; ".join(errors))

    # Save to TOML config
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        toml_content = f"""[ksm]
pages_to_scan = {config.pages_to_scan}
sleep_millisecs = {config.sleep_millisecs}
"""
        CONFIG_FILE.write_text(toml_content)
    except Exception as e:
        log.warning("Failed to save TOML config: %s", e)

    log.info("KSM config updated by %s: pages_to_scan=%d, sleep_millisecs=%d",
             user.get("sub"), config.pages_to_scan, config.sleep_millisecs)

    return {
        "success": True,
        "config": {
            "pages_to_scan": config.pages_to_scan,
            "sleep_millisecs": config.sleep_millisecs
        }
    }


app.include_router(router)
