"""SecuBox System Hub - Central System Management & Support
Dashboard, diagnostics, remote support, and system health monitoring.

Features:
- System health dashboard
- Service status aggregation
- Remote support (ttyd/rtty integration)
- Diagnostic collection and upload
- Support provider configuration
- Auto-upload for diagnostics
"""
import os
import json
import logging
import subprocess
import tarfile
import tempfile
import platform
import psutil
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/system-hub.toml")
DATA_DIR = Path("/var/lib/secubox/system-hub")
DIAG_DIR = DATA_DIR / "diagnostics"
CACHE_FILE = DATA_DIR / "status-cache.json"

app = FastAPI(title="SecuBox System Hub", version="1.0.0")
logger = logging.getLogger("secubox.system-hub")


class ServiceStatus(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"


class HealthLevel(str, Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class SupportSettings(BaseModel):
    provider: str = "CyberMind.fr"
    email: str = "support@cybermind.fr"
    docs_url: str = "https://docs.cybermind.fr"
    upload_url: Optional[str] = None
    auto_upload: bool = False
    remote_enabled: bool = False


class SystemInfo(BaseModel):
    hostname: str
    platform: str
    kernel: str
    architecture: str
    uptime: int
    boot_time: str
    cpu_count: int
    memory_total: int
    memory_available: int
    disk_total: int
    disk_free: int
    load_avg: List[float]


class ServiceInfo(BaseModel):
    name: str
    status: ServiceStatus
    enabled: bool
    pid: Optional[int] = None
    memory_mb: Optional[float] = None
    cpu_percent: Optional[float] = None
    uptime: Optional[int] = None


class DiagnosticBundle(BaseModel):
    id: str
    created_at: str
    size_bytes: int
    profile: str  # minimal, standard, full
    uploaded: bool = False
    uploaded_at: Optional[str] = None


class DiagnosticProfile(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


class SystemHub:
    """Central system management and support."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.diag_dir = data_dir / "diagnostics"
        self.cache_file = data_dir / "status-cache.json"
        self._ensure_dirs()
        self._load_settings()

        # SecuBox services to monitor
        self.secubox_services = [
            "secubox-ai-gateway",
            "secubox-localrecall",
            "secubox-identity",
            "secubox-master-link",
            "secubox-threat-analyst",
            "secubox-network-anomaly",
            "secubox-dns-guard",
            "secubox-cve-triage",
            "secubox-iot-guard",
            "secubox-config-advisor",
            "secubox-mcp-server",
        ]

        # Core services
        self.core_services = [
            "haproxy",
            "mitmproxy",
            "crowdsec",
            "suricata",
            "unbound",
            "nftables",
            "tailscaled",
        ]

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.diag_dir.mkdir(parents=True, exist_ok=True)

    def _load_settings(self):
        """Load support settings."""
        self.settings = SupportSettings()
        settings_file = self.data_dir / "settings.json"
        if settings_file.exists():
            try:
                data = json.loads(settings_file.read_text())
                self.settings = SupportSettings(**data)
            except Exception:
                pass

    def _save_settings(self):
        settings_file = self.data_dir / "settings.json"
        settings_file.write_text(json.dumps(self.settings.model_dump(), indent=2))

    def get_system_info(self) -> SystemInfo:
        """Get comprehensive system information."""
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = int((datetime.now() - boot_time).total_seconds())

        disk = psutil.disk_usage("/")
        memory = psutil.virtual_memory()

        return SystemInfo(
            hostname=platform.node(),
            platform=f"{platform.system()} {platform.release()}",
            kernel=platform.release(),
            architecture=platform.machine(),
            uptime=uptime,
            boot_time=boot_time.isoformat() + "Z",
            cpu_count=psutil.cpu_count(),
            memory_total=memory.total,
            memory_available=memory.available,
            disk_total=disk.total,
            disk_free=disk.free,
            load_avg=list(psutil.getloadavg())
        )

    def get_service_status(self, service_name: str) -> ServiceInfo:
        """Get status of a systemd service."""
        try:
            # Check if service is active
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            is_active = result.stdout.strip() == "active"

            # Check if enabled
            result = subprocess.run(
                ["systemctl", "is-enabled", service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            is_enabled = result.stdout.strip() == "enabled"

            status = ServiceStatus.RUNNING if is_active else ServiceStatus.STOPPED

            # Get PID and resource usage if running
            pid = None
            memory_mb = None
            cpu_percent = None
            uptime = None

            if is_active:
                result = subprocess.run(
                    ["systemctl", "show", service_name, "--property=MainPID"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                pid_str = result.stdout.strip().split("=")[-1]
                if pid_str and pid_str != "0":
                    pid = int(pid_str)
                    try:
                        proc = psutil.Process(pid)
                        memory_mb = proc.memory_info().rss / (1024 * 1024)
                        cpu_percent = proc.cpu_percent(interval=0.1)
                        uptime = int((datetime.now() - datetime.fromtimestamp(proc.create_time())).total_seconds())
                    except psutil.NoSuchProcess:
                        pass

            return ServiceInfo(
                name=service_name,
                status=status,
                enabled=is_enabled,
                pid=pid,
                memory_mb=round(memory_mb, 2) if memory_mb else None,
                cpu_percent=round(cpu_percent, 2) if cpu_percent else None,
                uptime=uptime
            )

        except Exception as e:
            logger.warning(f"Failed to get status for {service_name}: {e}")
            return ServiceInfo(
                name=service_name,
                status=ServiceStatus.UNKNOWN,
                enabled=False
            )

    def get_all_services(self) -> Dict[str, List[ServiceInfo]]:
        """Get status of all monitored services."""
        return {
            "secubox": [self.get_service_status(s) for s in self.secubox_services],
            "core": [self.get_service_status(s) for s in self.core_services]
        }

    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary."""
        services = self.get_all_services()
        system = self.get_system_info()

        # Count service states
        total = 0
        running = 0
        failed = 0

        for category in services.values():
            for svc in category:
                total += 1
                if svc.status == ServiceStatus.RUNNING:
                    running += 1
                elif svc.status == ServiceStatus.FAILED:
                    failed += 1

        # Determine overall health
        memory_percent = (1 - system.memory_available / system.memory_total) * 100
        disk_percent = (1 - system.disk_free / system.disk_total) * 100

        if failed > 0 or memory_percent > 95 or disk_percent > 95:
            health = HealthLevel.CRITICAL
        elif running < total or memory_percent > 80 or disk_percent > 80:
            health = HealthLevel.WARNING
        else:
            health = HealthLevel.HEALTHY

        return {
            "health": health.value,
            "services_total": total,
            "services_running": running,
            "services_failed": failed,
            "memory_percent": round(memory_percent, 1),
            "disk_percent": round(disk_percent, 1),
            "load_avg": system.load_avg[0],
            "uptime": system.uptime
        }

    def collect_diagnostics(self, profile: DiagnosticProfile = DiagnosticProfile.STANDARD) -> DiagnosticBundle:
        """Collect system diagnostics into a bundle."""
        now = datetime.utcnow()
        bundle_id = f"diag-{now.strftime('%Y%m%d-%H%M%S')}"
        bundle_path = self.diag_dir / f"{bundle_id}.tar.gz"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # System info
            (tmp / "system-info.json").write_text(json.dumps(
                self.get_system_info().model_dump(), indent=2
            ))

            # Service status
            (tmp / "services.json").write_text(json.dumps(
                {k: [s.model_dump() for s in v] for k, v in self.get_all_services().items()},
                indent=2
            ))

            # Health summary
            (tmp / "health.json").write_text(json.dumps(
                self.get_health_summary(), indent=2
            ))

            if profile in [DiagnosticProfile.STANDARD, DiagnosticProfile.FULL]:
                # Network info
                try:
                    result = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=10)
                    (tmp / "network-interfaces.txt").write_text(result.stdout)

                    result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=10)
                    (tmp / "network-routes.txt").write_text(result.stdout)

                    result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=10)
                    (tmp / "network-ports.txt").write_text(result.stdout)
                except Exception:
                    pass

                # Firewall rules
                try:
                    result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=10)
                    (tmp / "firewall-rules.txt").write_text(result.stdout)
                except Exception:
                    pass

            if profile == DiagnosticProfile.FULL:
                # Recent logs
                try:
                    result = subprocess.run(
                        ["journalctl", "-u", "secubox-*", "--since", "1 hour ago", "--no-pager"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    (tmp / "secubox-logs.txt").write_text(result.stdout)

                    result = subprocess.run(
                        ["journalctl", "--since", "1 hour ago", "--no-pager", "-p", "err"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    (tmp / "system-errors.txt").write_text(result.stdout)
                except Exception:
                    pass

                # Process list
                try:
                    result = subprocess.run(["ps", "auxww"], capture_output=True, text=True, timeout=10)
                    (tmp / "processes.txt").write_text(result.stdout)
                except Exception:
                    pass

            # Create tarball
            with tarfile.open(bundle_path, "w:gz") as tar:
                for f in tmp.iterdir():
                    tar.add(f, arcname=f.name)

        bundle = DiagnosticBundle(
            id=bundle_id,
            created_at=now.isoformat() + "Z",
            size_bytes=bundle_path.stat().st_size,
            profile=profile.value
        )

        return bundle

    async def upload_diagnostics(self, bundle_id: str) -> bool:
        """Upload diagnostic bundle to support server."""
        if not self.settings.upload_url:
            return False

        bundle_path = self.diag_dir / f"{bundle_id}.tar.gz"
        if not bundle_path.exists():
            return False

        try:
            async with httpx.AsyncClient() as client:
                with open(bundle_path, "rb") as f:
                    response = await client.post(
                        self.settings.upload_url,
                        files={"diagnostics": (f"{bundle_id}.tar.gz", f, "application/gzip")},
                        timeout=60.0
                    )
                return response.status_code in [200, 201, 202]
        except Exception as e:
            logger.error(f"Diagnostic upload failed: {e}")
            return False

    def list_diagnostics(self) -> List[DiagnosticBundle]:
        """List available diagnostic bundles."""
        bundles = []
        for f in self.diag_dir.glob("diag-*.tar.gz"):
            try:
                # Parse ID and timestamp from filename
                bundle_id = f.stem
                parts = bundle_id.split("-")
                if len(parts) >= 3:
                    date_str = parts[1]
                    time_str = parts[2].replace(".tar", "")
                    created = datetime.strptime(f"{date_str}-{time_str}", "%Y%m%d-%H%M%S")

                    bundles.append(DiagnosticBundle(
                        id=bundle_id,
                        created_at=created.isoformat() + "Z",
                        size_bytes=f.stat().st_size,
                        profile="unknown"
                    ))
            except Exception:
                continue

        return sorted(bundles, key=lambda x: x.created_at, reverse=True)

    def get_remote_support_status(self) -> Dict[str, Any]:
        """Check remote support (ttyd) status."""
        status = {
            "ttyd_installed": False,
            "ttyd_running": False,
            "ttyd_port": 7681,
            "remote_enabled": self.settings.remote_enabled
        }

        # Check ttyd
        try:
            result = subprocess.run(["which", "ttyd"], capture_output=True, timeout=5)
            status["ttyd_installed"] = result.returncode == 0

            result = subprocess.run(
                ["systemctl", "is-active", "ttyd"],
                capture_output=True,
                text=True,
                timeout=5
            )
            status["ttyd_running"] = result.stdout.strip() == "active"
        except Exception:
            pass

        return status

    def service_action(self, service: str, action: str) -> bool:
        """Perform action on a service (start/stop/restart/enable/disable)."""
        if action not in ["start", "stop", "restart", "enable", "disable"]:
            return False

        if service not in self.secubox_services + self.core_services:
            return False

        try:
            subprocess.run(
                ["systemctl", action, service],
                capture_output=True,
                timeout=30,
                check=True
            )
            return True
        except Exception as e:
            logger.error(f"Service action {action} on {service} failed: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get system hub statistics."""
        health = self.get_health_summary()
        diagnostics = self.list_diagnostics()

        return {
            "health": health["health"],
            "services_running": health["services_running"],
            "services_total": health["services_total"],
            "diagnostics_count": len(diagnostics),
            "remote_enabled": self.settings.remote_enabled
        }


# Global instance
hub = SystemHub(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = hub.get_stats()
    return {
        "module": "system-hub",
        "status": "ok",
        "version": "1.0.0",
        "health": stats["health"],
        "services_running": stats["services_running"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get system hub statistics."""
    return hub.get_stats()


@app.get("/system", dependencies=[Depends(require_jwt)])
async def get_system_info():
    """Get system information."""
    return hub.get_system_info()


@app.get("/health/summary", dependencies=[Depends(require_jwt)])
async def get_health_summary():
    """Get health summary."""
    return hub.get_health_summary()


@app.get("/services", dependencies=[Depends(require_jwt)])
async def list_services():
    """List all monitored services."""
    return hub.get_all_services()


@app.get("/services/{service_name}", dependencies=[Depends(require_jwt)])
async def get_service(service_name: str):
    """Get specific service status."""
    return hub.get_service_status(service_name)


@app.post("/services/{service_name}/{action}", dependencies=[Depends(require_jwt)])
async def service_action(service_name: str, action: str):
    """Perform service action (start/stop/restart/enable/disable)."""
    if hub.service_action(service_name, action):
        return {"status": "success", "action": action, "service": service_name}
    raise HTTPException(status_code=400, detail="Action failed")


@app.get("/support/settings", dependencies=[Depends(require_jwt)])
async def get_support_settings():
    """Get support settings."""
    return hub.settings


@app.put("/support/settings", dependencies=[Depends(require_jwt)])
async def update_support_settings(settings: SupportSettings):
    """Update support settings."""
    hub.settings = settings
    hub._save_settings()
    return {"status": "updated"}


@app.get("/support/remote", dependencies=[Depends(require_jwt)])
async def get_remote_status():
    """Get remote support status."""
    return hub.get_remote_support_status()


@app.post("/support/remote/{action}", dependencies=[Depends(require_jwt)])
async def remote_action(action: str):
    """Control remote support (enable/disable)."""
    if action == "enable":
        hub.settings.remote_enabled = True
        hub._save_settings()
        hub.service_action("ttyd", "start")
        return {"status": "enabled"}
    elif action == "disable":
        hub.settings.remote_enabled = False
        hub._save_settings()
        hub.service_action("ttyd", "stop")
        return {"status": "disabled"}
    raise HTTPException(status_code=400, detail="Invalid action")


@app.get("/diagnostics", dependencies=[Depends(require_jwt)])
async def list_diagnostics():
    """List diagnostic bundles."""
    return {"diagnostics": hub.list_diagnostics()}


@app.post("/diagnostics/collect", dependencies=[Depends(require_jwt)])
async def collect_diagnostics(profile: DiagnosticProfile = DiagnosticProfile.STANDARD):
    """Collect new diagnostic bundle."""
    bundle = hub.collect_diagnostics(profile)
    return {"status": "collected", "bundle": bundle}


@app.get("/diagnostics/{bundle_id}/download", dependencies=[Depends(require_jwt)])
async def download_diagnostics(bundle_id: str):
    """Download diagnostic bundle."""
    bundle_path = hub.diag_dir / f"{bundle_id}.tar.gz"
    if not bundle_path.exists():
        raise HTTPException(status_code=404, detail="Bundle not found")
    return FileResponse(
        bundle_path,
        media_type="application/gzip",
        filename=f"{bundle_id}.tar.gz"
    )


@app.post("/diagnostics/{bundle_id}/upload", dependencies=[Depends(require_jwt)])
async def upload_diagnostics(bundle_id: str):
    """Upload diagnostic bundle to support server."""
    if not hub.settings.upload_url:
        raise HTTPException(status_code=400, detail="Upload URL not configured")

    success = await hub.upload_diagnostics(bundle_id)
    if success:
        return {"status": "uploaded"}
    raise HTTPException(status_code=500, detail="Upload failed")


@app.delete("/diagnostics/{bundle_id}", dependencies=[Depends(require_jwt)])
async def delete_diagnostics(bundle_id: str):
    """Delete diagnostic bundle."""
    bundle_path = hub.diag_dir / f"{bundle_id}.tar.gz"
    if not bundle_path.exists():
        raise HTTPException(status_code=404, detail="Bundle not found")
    bundle_path.unlink()
    return {"status": "deleted"}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("System Hub started")
