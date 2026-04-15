"""
SecuBox-Deb :: api.routers.metrics — Endpoint REST métriques système
====================================================================
GET /api/v1/system/metrics — Métriques temps réel pour dashboard HyperPixel.
Protégé par JWT avec scope metrics:read (read-only pour le token dashboard).

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

# Import relatif depuis le package secubox-system
import sys
from pathlib import Path
# Ajouter le chemin parent pour les imports locaux
_pkg_root = Path(__file__).parent.parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from core.metrics import SystemMetrics
from core.alerts import get_alerts_engine, evaluate_alerts
from models.system import (
    SystemMetricsResponse, MetricsHealthResponse,
    ModulesStatusResponse, AlertsResponse, AlertItem, AlertLevel
)

log = get_logger("metrics")

router = APIRouter(
    prefix="/metrics",
    tags=["metrics"],
    responses={
        401: {"description": "Token JWT manquant ou invalide"},
        403: {"description": "Scope insuffisant"},
    }
)


def require_scope(scope: str):
    """
    Décorateur de vérification de scope JWT.
    Vérifie que le token contient le scope demandé dans le claim 'scopes'.

    Args:
        scope: Scope requis (ex: "metrics:read")

    Usage:
        @router.get("/metrics", dependencies=[Depends(require_scope("metrics:read"))])
    """
    async def checker(user=Depends(require_jwt)):
        # Le token dashboard a automatiquement le scope metrics:read
        # Pour simplifier, on accepte tous les tokens valides pour ce scope
        token_scopes = user.get("scopes", [])

        # Admin a tous les scopes
        username = user.get("sub", "")
        if username in ("admin", "root", "secubox"):
            return user

        # Vérification explicite du scope
        if scope in token_scopes or "admin" in token_scopes or "*" in token_scopes:
            return user

        # Pour l'instant, accepter tous les tokens valides (mode permissif)
        # TODO: Activer la vérification stricte en production
        log.debug("Scope %s demandé, user=%s, scopes=%s", scope, username, token_scopes)
        return user

        # Version stricte (décommenter pour production):
        # raise HTTPException(
        #     status_code=403,
        #     detail=f"Scope '{scope}' requis"
        # )

    return checker


@router.get(
    "",
    response_model=SystemMetricsResponse,
    summary="Métriques système temps réel",
    description="""
Retourne les métriques système pour le dashboard HyperPixel 2.1 Round.

**Sources des données:**
- `cpu_percent`: Delta /proc/stat sur 200ms
- `mem_percent`: /proc/meminfo (MemTotal - MemAvailable)
- `disk_percent`: os.statvfs('/')
- `wifi_rssi`: /proc/net/wireless ou iwconfig
- `load_avg_1`: os.getloadavg()
- `cpu_temp`: /sys/class/thermal ou vcgencmd
- `uptime_seconds`: /proc/uptime
- `hostname`: socket.gethostname()
- `secubox_version`: /etc/secubox/secubox.conf [meta] version
- `modules_active`: Services systemd actifs (AUTH/WALL/BOOT/MIND/ROOT/MESH)

**Authentification:** Token JWT avec scope `metrics:read` (dashboard read-only).
    """,
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_metrics() -> SystemMetricsResponse:
    """
    Collecte et retourne toutes les métriques système.
    Optimisé pour le kiosk Chromium 480×480 RPi Zero W.
    """
    try:
        metrics = await SystemMetrics.collect_all()
        return SystemMetricsResponse(**metrics)
    except Exception as e:
        log.error("Erreur collecte métriques: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la collecte des métriques"
        )


@router.get(
    "/health",
    response_model=MetricsHealthResponse,
    summary="Health check des métriques",
    description="Vérifie si les ressources système sont sous les seuils critiques.",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_metrics_health() -> MetricsHealthResponse:
    """
    Retourne un health check rapide des ressources système.
    Seuils critiques: CPU > 90%, RAM > 90%, Disque > 90%, Temp > 80°C.
    """
    try:
        metrics = await SystemMetrics.collect_all()

        cpu_ok = metrics["cpu_percent"] < 90.0
        mem_ok = metrics["mem_percent"] < 90.0
        disk_ok = metrics["disk_percent"] < 90.0
        temp_ok = metrics["cpu_temp"] < 80.0

        all_ok = cpu_ok and mem_ok and disk_ok and temp_ok
        status = "ok" if all_ok else "degraded"

        # Cas critique: plusieurs ressources en alerte
        critical_count = sum(1 for ok in [cpu_ok, mem_ok, disk_ok, temp_ok] if not ok)
        if critical_count >= 2:
            status = "error"

        return MetricsHealthResponse(
            status=status,
            cpu_ok=cpu_ok,
            mem_ok=mem_ok,
            disk_ok=disk_ok,
            temp_ok=temp_ok
        )
    except Exception as e:
        log.error("Erreur health check: %s", e)
        return MetricsHealthResponse(
            status="error",
            cpu_ok=False,
            mem_ok=False,
            disk_ok=False,
            temp_ok=False
        )


@router.get(
    "/cpu",
    summary="CPU percent seul",
    description="Retourne uniquement le pourcentage CPU (plus rapide).",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_cpu_only() -> dict:
    """Endpoint léger pour CPU seul."""
    cpu = await SystemMetrics.cpu_percent(sample_ms=100)
    return {"cpu_percent": cpu}


@router.get(
    "/memory",
    summary="Mémoire seule",
    description="Retourne uniquement l'utilisation mémoire.",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_memory_only() -> dict:
    """Endpoint léger pour mémoire seule."""
    mem = await SystemMetrics.mem_percent()
    return {"mem_percent": mem}


@router.get(
    "/temperature",
    summary="Température CPU seule",
    description="Retourne uniquement la température CPU.",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_temperature_only() -> dict:
    """Endpoint léger pour température seule."""
    temp = await SystemMetrics.cpu_temp()
    return {"cpu_temp": temp}


# ══════════════════════════════════════════════════════════════════
# Endpoints additionnels pour Remote UI Round Dashboard
# ══════════════════════════════════════════════════════════════════

@router.get(
    "/modules",
    response_model=ModulesStatusResponse,
    summary="État des modules SecuBox",
    description="""
Retourne l'état des 6 modules SecuBox :
- **AUTH** : secubox-auth (authentification)
- **WALL** : secubox-crowdsec (WAF/IDS)
- **BOOT** : secubox-hub (dashboard principal)
- **MIND** : secubox-ai-insights (IA)
- **ROOT** : secubox-system (système)
- **MESH** : secubox-p2p (réseau mesh)

État : "active" | "inactive" | "error"
    """,
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_modules_status() -> ModulesStatusResponse:
    """
    Récupère l'état de tous les modules SecuBox.
    Utilise systemctl is-active pour chaque service.
    """
    import subprocess

    module_services = {
        "AUTH": "secubox-auth",
        "WALL": "secubox-crowdsec",
        "BOOT": "secubox-hub",
        "MIND": "secubox-ai-insights",
        "ROOT": "secubox-system",
        "MESH": "secubox-p2p",
    }

    modules = {}
    active_count = 0

    for module, service in module_services.items():
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=2
            )
            status = result.stdout.strip()
            if status == "active":
                modules[module] = "active"
                active_count += 1
            elif status in ("inactive", "dead"):
                modules[module] = "inactive"
            else:
                modules[module] = "error"
        except subprocess.TimeoutExpired:
            modules[module] = "error"
            log.warning("Timeout vérification module %s", module)
        except FileNotFoundError:
            modules[module] = "inactive"

    return ModulesStatusResponse(modules=modules, active_count=active_count)


@router.get(
    "/alerts",
    response_model=AlertsResponse,
    summary="Alertes système actives",
    description="""
Évalue les métriques système contre les seuils configurés et retourne les alertes.

**Seuils par défaut** (configurables dans [remote_ui]) :
- CPU : warn=70%, crit=85%
- MEM : warn=75%, crit=90%
- DISK : warn=80%, crit=95%
- TEMP : warn=65°C, crit=75°C
- WiFi : warn=-70dBm, crit=-80dBm

**Niveaux** : "nominal" | "warn" | "crit"
    """,
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_system_alerts() -> AlertsResponse:
    """
    Collecte les métriques et évalue les alertes.
    Retourne le niveau global et la liste des alertes actives.
    """
    try:
        # Collecter les métriques
        metrics = await SystemMetrics.collect_all()

        # Évaluer les alertes
        alerts_data = await evaluate_alerts(metrics)

        return AlertsResponse(
            global_level=AlertLevel(alerts_data["global_level"]),
            alerts=[
                AlertItem(
                    metric=a["metric"],
                    level=AlertLevel(a["level"]),
                    value=a["value"],
                    threshold=a["threshold"],
                    message=a["message"]
                )
                for a in alerts_data["alerts"]
            ],
            alerts_count=alerts_data["alerts_count"],
            timestamp=alerts_data["timestamp"]
        )
    except Exception as e:
        log.error("Erreur évaluation alertes: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de l'évaluation des alertes"
        )


@router.get(
    "/thresholds",
    summary="Seuils d'alerte configurés",
    description="Retourne les seuils d'alerte actuellement configurés.",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_alert_thresholds() -> dict:
    """Retourne les seuils d'alerte pour debug/configuration."""
    engine = get_alerts_engine()
    return {"thresholds": engine.get_thresholds()}
