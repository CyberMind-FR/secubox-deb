"""
SecuBox-Deb :: models.system — Schémas Pydantic pour les métriques système
==========================================================================
Définit les modèles de réponse pour l'endpoint /api/v1/system/metrics.
Optimisé pour le dashboard HyperPixel 2.1 Round (480×480).

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class SystemMetricsResponse(BaseModel):
    """
    Réponse de l'endpoint GET /api/v1/system/metrics.
    Toutes les métriques temps réel pour le dashboard kiosk.

    Attributs:
        cpu_percent: Usage CPU instantané en % (0.0-100.0)
        mem_percent: RAM utilisée en % (0.0-100.0)
        disk_percent: Disque / utilisé en % (0.0-100.0)
        wifi_rssi: Signal WiFi en dBm (négatif), 0 si filaire
        load_avg_1: Load average 1 minute
        cpu_temp: Température CPU en °C
        uptime_seconds: Uptime système en secondes
        hostname: Nom de la machine
        secubox_version: Version SecuBox depuis /etc/secubox/secubox.conf
        modules_active: Liste des modules SecuBox actifs (AUTH/WALL/BOOT/MIND/ROOT/MESH)
    """

    cpu_percent: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Usage CPU instantané en pourcentage",
        json_schema_extra={"example": 23.5}
    )

    mem_percent: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="RAM utilisée en pourcentage",
        json_schema_extra={"example": 67.2}
    )

    disk_percent: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Espace disque utilisé en pourcentage",
        json_schema_extra={"example": 45.8}
    )

    wifi_rssi: int = Field(
        default=0,
        le=0,
        description="Signal WiFi en dBm (négatif), 0 si connexion filaire",
        json_schema_extra={"example": -52}
    )

    load_avg_1: float = Field(
        default=0.0,
        ge=0.0,
        description="Load average sur 1 minute",
        json_schema_extra={"example": 0.45}
    )

    cpu_temp: float = Field(
        default=0.0,
        ge=0.0,
        le=150.0,
        description="Température CPU en degrés Celsius",
        json_schema_extra={"example": 48.3}
    )

    uptime_seconds: int = Field(
        default=0,
        ge=0,
        description="Uptime système en secondes",
        json_schema_extra={"example": 86400}
    )

    hostname: str = Field(
        default="secubox",
        description="Nom d'hôte de la machine",
        json_schema_extra={"example": "secubox-hub"}
    )

    secubox_version: str = Field(
        default="2.0.0",
        description="Version SecuBox depuis la configuration",
        json_schema_extra={"example": "2.0.0"}
    )

    modules_active: List[str] = Field(
        default_factory=list,
        description="Liste des modules SecuBox actifs",
        json_schema_extra={"example": ["AUTH", "WALL", "BOOT", "ROOT"]}
    )

    class Config:
        """Configuration du modèle Pydantic."""
        json_schema_extra = {
            "example": {
                "cpu_percent": 23.5,
                "mem_percent": 67.2,
                "disk_percent": 45.8,
                "wifi_rssi": -52,
                "load_avg_1": 0.45,
                "cpu_temp": 48.3,
                "uptime_seconds": 86400,
                "hostname": "secubox-hub",
                "secubox_version": "2.0.0",
                "modules_active": ["AUTH", "WALL", "BOOT", "ROOT"]
            }
        }


class MetricsHealthResponse(BaseModel):
    """
    Réponse simplifiée pour health check rapide.
    Utilisé par le monitoring interne.
    """

    status: str = Field(
        default="ok",
        description="État du service (ok/degraded/error)"
    )

    cpu_ok: bool = Field(
        default=True,
        description="CPU sous le seuil critique (< 90%)"
    )

    mem_ok: bool = Field(
        default=True,
        description="Mémoire sous le seuil critique (< 90%)"
    )

    disk_ok: bool = Field(
        default=True,
        description="Disque sous le seuil critique (< 90%)"
    )

    temp_ok: bool = Field(
        default=True,
        description="Température sous le seuil critique (< 80°C)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "status": "ok",
                "cpu_ok": True,
                "mem_ok": True,
                "disk_ok": True,
                "temp_ok": True
            }
        }


# ══════════════════════════════════════════════════════════════════
# Schémas additionnels pour Remote UI Round Dashboard
# ══════════════════════════════════════════════════════════════════

from typing import Dict, Literal
from enum import Enum


class ModuleStatus(str, Enum):
    """État d'un module SecuBox."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class AlertLevel(str, Enum):
    """Niveau d'alerte système."""
    NOMINAL = "nominal"
    WARN = "warn"
    CRIT = "crit"


class ModulesStatusResponse(BaseModel):
    """
    Réponse de GET /api/v1/system/modules.
    État des 6 modules SecuBox : AUTH, WALL, BOOT, MIND, ROOT, MESH.
    """

    modules: Dict[str, ModuleStatus] = Field(
        default_factory=dict,
        description="Dict module → état (active/inactive/error)",
        json_schema_extra={
            "example": {
                "AUTH": "active",
                "WALL": "active",
                "BOOT": "active",
                "MIND": "inactive",
                "ROOT": "active",
                "MESH": "error"
            }
        }
    )

    active_count: int = Field(
        default=0,
        ge=0,
        le=6,
        description="Nombre de modules actifs"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "modules": {
                    "AUTH": "active",
                    "WALL": "active",
                    "BOOT": "active",
                    "MIND": "inactive",
                    "ROOT": "active",
                    "MESH": "active"
                },
                "active_count": 5
            }
        }


class AlertItem(BaseModel):
    """
    Item d'alerte individuel.
    Représente une métrique dépassant un seuil.
    """

    metric: str = Field(
        ...,
        description="Nom de la métrique (cpu, mem, disk, temp, wifi)",
        json_schema_extra={"example": "cpu"}
    )

    level: AlertLevel = Field(
        default=AlertLevel.NOMINAL,
        description="Niveau d'alerte (nominal/warn/crit)"
    )

    value: float = Field(
        ...,
        description="Valeur actuelle de la métrique",
        json_schema_extra={"example": 87.5}
    )

    threshold: float = Field(
        ...,
        description="Seuil dépassé",
        json_schema_extra={"example": 85.0}
    )

    message: str = Field(
        default="",
        description="Message d'alerte formaté",
        json_schema_extra={"example": "CPU 87% > seuil critique 85%"}
    )

    class Config:
        json_schema_extra = {
            "example": {
                "metric": "cpu",
                "level": "crit",
                "value": 87.5,
                "threshold": 85.0,
                "message": "CPU 87% > seuil critique 85%"
            }
        }


class AlertsResponse(BaseModel):
    """
    Réponse de GET /api/v1/system/alerts.
    Agrégation de toutes les alertes actives.
    """

    global_level: AlertLevel = Field(
        default=AlertLevel.NOMINAL,
        description="Niveau global (pire niveau parmi les alertes)"
    )

    alerts: List[AlertItem] = Field(
        default_factory=list,
        description="Liste des alertes actives"
    )

    alerts_count: int = Field(
        default=0,
        ge=0,
        description="Nombre d'alertes actives"
    )

    timestamp: str = Field(
        default="",
        description="Timestamp ISO 8601 de l'évaluation",
        json_schema_extra={"example": "2026-04-15T10:30:00Z"}
    )

    class Config:
        json_schema_extra = {
            "example": {
                "global_level": "warn",
                "alerts": [
                    {
                        "metric": "cpu",
                        "level": "warn",
                        "value": 72.5,
                        "threshold": 70.0,
                        "message": "CPU 72% > seuil avertissement 70%"
                    }
                ],
                "alerts_count": 1,
                "timestamp": "2026-04-15T10:30:00Z"
            }
        }


# ══════════════════════════════════════════════════════════════════
# Remote UI OTG Transport Status
# ══════════════════════════════════════════════════════════════════

class TransportType(str, Enum):
    """Type de transport Remote UI."""
    OTG = "otg"
    WIFI = "wifi"
    NONE = "none"


class RemoteUIConnectedRequest(BaseModel):
    """
    Requête POST /api/v1/remote-ui/connected.
    Envoyée par le script udev côté hôte lors de la connexion OTG.
    """

    transport: TransportType = Field(
        ...,
        description="Type de transport (otg/wifi)"
    )

    peer: str = Field(
        ...,
        description="Adresse IP du peer Remote UI",
        json_schema_extra={"example": "10.55.0.2"}
    )

    interface: str = Field(
        default="secubox-round",
        description="Nom de l'interface réseau",
        json_schema_extra={"example": "secubox-round"}
    )

    class Config:
        json_schema_extra = {
            "example": {
                "transport": "otg",
                "peer": "10.55.0.2",
                "interface": "secubox-round"
            }
        }


class RemoteUIStatusResponse(BaseModel):
    """
    Réponse de GET /api/v1/remote-ui/status.
    État de la connexion Remote UI (OTG ou WiFi).
    """

    connected: bool = Field(
        default=False,
        description="Remote UI connecté"
    )

    transport: TransportType = Field(
        default=TransportType.NONE,
        description="Transport actif (otg/wifi/none)"
    )

    peer_ip: str = Field(
        default="",
        description="Adresse IP du Remote UI",
        json_schema_extra={"example": "10.55.0.2"}
    )

    interface: str = Field(
        default="",
        description="Interface réseau utilisée",
        json_schema_extra={"example": "secubox-round"}
    )

    uptime_seconds: int = Field(
        default=0,
        ge=0,
        description="Durée de connexion en secondes"
    )

    last_seen: str = Field(
        default="",
        description="Timestamp ISO 8601 du dernier contact",
        json_schema_extra={"example": "2026-04-15T10:30:00Z"}
    )

    serial_available: bool = Field(
        default=False,
        description="Console série disponible (/dev/secubox-console)"
    )

    serial_device: str = Field(
        default="",
        description="Device de la console série",
        json_schema_extra={"example": "/dev/ttyACM0"}
    )

    class Config:
        json_schema_extra = {
            "example": {
                "connected": True,
                "transport": "otg",
                "peer_ip": "10.55.0.2",
                "interface": "secubox-round",
                "uptime_seconds": 3600,
                "last_seen": "2026-04-15T10:30:00Z",
                "serial_available": True,
                "serial_device": "/dev/ttyACM0"
            }
        }
