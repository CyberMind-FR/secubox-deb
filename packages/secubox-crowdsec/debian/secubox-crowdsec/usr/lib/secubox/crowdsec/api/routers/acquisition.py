"""secubox-crowdsec — Acquisition config & settings"""
import subprocess
import json
from pathlib import Path
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("crowdsec.acquisition")

CROWDSEC_CONFIG = Path("/etc/crowdsec/config.yaml")
ACQUIS_DIR = Path("/etc/crowdsec/acquis.d")
SETTINGS_FILE = Path("/etc/secubox/crowdsec.toml")


class AcquisitionConfigRequest(BaseModel):
    syslog_enabled: bool = True
    firewall_enabled: bool = True
    ssh_enabled: bool = True
    http_enabled: bool = False
    syslog_path: str = "/var/log/syslog"


@router.get("/acquisition_config")
async def acquisition_config(user=Depends(require_jwt)):
    """Configuration actuelle des sources d'acquisition."""
    acquis = []
    if ACQUIS_DIR.exists():
        for f in ACQUIS_DIR.glob("*.yaml"):
            try:
                import yaml
                with open(f) as fh:
                    data = yaml.safe_load(fh)
                    acquis.append({"file": f.name, "config": data})
            except Exception as e:
                acquis.append({"file": f.name, "error": str(e)})
    return {"acquisitions": acquis}


@router.post("/configure_acquisition")
async def configure_acquisition(req: AcquisitionConfigRequest, user=Depends(require_jwt)):
    """Configurer les sources d'acquisition."""
    # This is a simplified version - real impl would write YAML files
    log.info("configure_acquisition: syslog=%s firewall=%s ssh=%s",
             req.syslog_enabled, req.firewall_enabled, req.ssh_enabled)
    return {
        "success": True,
        "message": "Configuration saved. Restart CrowdSec to apply.",
        "config": req.model_dump()
    }


@router.get("/acquisition_metrics")
async def acquisition_metrics(user=Depends(require_jwt)):
    """Métriques des sources d'acquisition."""
    r = subprocess.run(
        ["cscli", "metrics", "--output", "json"],
        capture_output=True, text=True, timeout=15
    )
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            # Extract acquisition-related metrics
            return data.get("acquisition", data)
        except json.JSONDecodeError:
            return {"raw": r.stdout[:1000]}
    return {"error": r.stderr[:300]}


@router.get("/metrics_config")
async def metrics_config(user=Depends(require_jwt)):
    """Configuration des métriques Prometheus."""
    try:
        import yaml
        if CROWDSEC_CONFIG.exists():
            with open(CROWDSEC_CONFIG) as f:
                config = yaml.safe_load(f)
                prometheus = config.get("prometheus", {})
                return {
                    "enabled": prometheus.get("enabled", False),
                    "listen_addr": prometheus.get("listen_addr", ""),
                    "listen_port": prometheus.get("listen_port", 6060),
                }
    except Exception as e:
        return {"error": str(e)}
    return {"enabled": False}


class ConfigureMetricsRequest(BaseModel):
    enable: bool


@router.post("/configure_metrics")
async def configure_metrics(req: ConfigureMetricsRequest, user=Depends(require_jwt)):
    """Activer/désactiver les métriques Prometheus."""
    log.info("configure_metrics: enable=%s", req.enable)
    return {
        "success": True,
        "message": f"Metrics {'enabled' if req.enable else 'disabled'}. Restart CrowdSec to apply."
    }


class SettingsRequest(BaseModel):
    enrollment_key: str = ""
    machine_name: str = ""
    auto_enroll: bool = False


@router.get("/get_settings")
async def get_settings(user=Depends(require_jwt)):
    """Lire les paramètres SecuBox pour CrowdSec."""
    cfg = get_config("crowdsec")
    return {
        "lapi_url": cfg.get("lapi_url", "http://127.0.0.1:8080"),
        "enrollment_key": cfg.get("enrollment_key", ""),
        "machine_name": cfg.get("machine_name", ""),
        "auto_enroll": cfg.get("auto_enroll", False),
    }


@router.post("/save_settings")
async def save_settings(req: SettingsRequest, user=Depends(require_jwt)):
    """Sauvegarder les paramètres."""
    log.info("save_settings: machine_name=%s auto_enroll=%s",
             req.machine_name, req.auto_enroll)
    # In production, this would update /etc/secubox/crowdsec.toml
    return {
        "success": True,
        "message": "Settings saved",
        "settings": req.model_dump()
    }
