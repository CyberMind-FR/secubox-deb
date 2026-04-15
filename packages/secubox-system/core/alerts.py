"""
SecuBox-Deb :: core.alerts — Moteur d'évaluation des alertes système
====================================================================
Évalue les métriques contre les seuils configurés et produit des alertes.
Les seuils sont configurables dans /etc/secubox/secubox.conf [remote_ui].

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from secubox_core.config import get_config
from secubox_core.logger import get_logger

log = get_logger("alerts")


@dataclass
class AlertThresholds:
    """
    Seuils d'alerte par défaut.
    Configurables dans [remote_ui] de secubox.conf.

    PARAMETERS 4R : Ces seuils peuvent être modifiés via l'API.
    Rollback possible vers les valeurs par défaut.
    """
    cpu_warn: float = 70.0
    cpu_crit: float = 85.0
    mem_warn: float = 75.0
    mem_crit: float = 90.0
    disk_warn: float = 80.0
    disk_crit: float = 95.0
    temp_warn: float = 65.0
    temp_crit: float = 75.0
    # WiFi : signal faible si > -70 dBm (plus proche de 0 = meilleur)
    wifi_warn: int = -70
    wifi_crit: int = -80


class AlertItem:
    """
    Représentation d'une alerte individuelle.
    """
    def __init__(
        self,
        metric: str,
        level: str,
        value: float,
        threshold: float,
        message: str = ""
    ):
        self.metric = metric
        self.level = level  # "nominal" | "warn" | "crit"
        self.value = value
        self.threshold = threshold
        self.message = message or self._default_message()

    def _default_message(self) -> str:
        """Génère un message par défaut."""
        level_fr = {"warn": "avertissement", "crit": "critique", "nominal": "nominal"}
        return f"{self.metric.upper()} {self.value:.0f}% > seuil {level_fr.get(self.level, '')} {self.threshold:.0f}%"

    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dict pour sérialisation JSON."""
        return {
            "metric": self.metric,
            "level": self.level,
            "value": self.value,
            "threshold": self.threshold,
            "message": self.message
        }


class AlertsEngine:
    """
    Moteur d'évaluation des alertes système.
    Compare les métriques aux seuils et produit des AlertItem.

    Usage:
        engine = AlertsEngine()
        alerts = await engine.evaluate(metrics)
    """

    def __init__(self, thresholds: Optional[AlertThresholds] = None):
        """
        Initialise le moteur avec les seuils.
        Si non fournis, charge depuis la configuration.
        """
        self.thresholds = thresholds or self._load_thresholds()

    def _load_thresholds(self) -> AlertThresholds:
        """
        Charge les seuils depuis [remote_ui] de secubox.conf.
        Utilise les valeurs par défaut si non configurées.
        """
        try:
            cfg = get_config("remote_ui")
            return AlertThresholds(
                cpu_warn=float(cfg.get("cpu_warn", 70)),
                cpu_crit=float(cfg.get("cpu_crit", 85)),
                mem_warn=float(cfg.get("mem_warn", 75)),
                mem_crit=float(cfg.get("mem_crit", 90)),
                disk_warn=float(cfg.get("disk_warn", 80)),
                disk_crit=float(cfg.get("disk_crit", 95)),
                temp_warn=float(cfg.get("temp_warn", 65)),
                temp_crit=float(cfg.get("temp_crit", 75)),
                wifi_warn=int(cfg.get("wifi_warn", -70)),
                wifi_crit=int(cfg.get("wifi_crit", -80)),
            )
        except Exception as e:
            log.warning("Erreur chargement seuils: %s — valeurs par défaut", e)
            return AlertThresholds()

    def _evaluate_metric(
        self,
        name: str,
        value: float,
        warn_threshold: float,
        crit_threshold: float,
        higher_is_worse: bool = True
    ) -> Optional[AlertItem]:
        """
        Évalue une métrique contre ses seuils.

        Args:
            name: Nom de la métrique
            value: Valeur actuelle
            warn_threshold: Seuil d'avertissement
            crit_threshold: Seuil critique
            higher_is_worse: True si valeur haute = pire (CPU, MEM, DISK, TEMP)
                            False si valeur basse = pire (WiFi RSSI)

        Returns:
            AlertItem si seuil dépassé, None sinon
        """
        if higher_is_worse:
            if value >= crit_threshold:
                return AlertItem(
                    metric=name,
                    level="crit",
                    value=value,
                    threshold=crit_threshold,
                    message=f"{name.upper()} {value:.0f}% > seuil critique {crit_threshold:.0f}%"
                )
            elif value >= warn_threshold:
                return AlertItem(
                    metric=name,
                    level="warn",
                    value=value,
                    threshold=warn_threshold,
                    message=f"{name.upper()} {value:.0f}% > seuil avertissement {warn_threshold:.0f}%"
                )
        else:
            # Pour WiFi RSSI : plus négatif = pire signal
            if value <= crit_threshold:
                return AlertItem(
                    metric=name,
                    level="crit",
                    value=value,
                    threshold=crit_threshold,
                    message=f"{name.upper()} {value:.0f} dBm < seuil critique {crit_threshold:.0f} dBm"
                )
            elif value <= warn_threshold:
                return AlertItem(
                    metric=name,
                    level="warn",
                    value=value,
                    threshold=warn_threshold,
                    message=f"{name.upper()} {value:.0f} dBm < seuil avertissement {warn_threshold:.0f} dBm"
                )

        return None

    async def evaluate(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Évalue toutes les métriques et retourne les alertes.

        Args:
            metrics: Dict contenant cpu_percent, mem_percent, disk_percent,
                    cpu_temp, wifi_rssi, etc.

        Returns:
            Dict avec global_level, alerts, alerts_count, timestamp
        """
        alerts: List[AlertItem] = []
        th = self.thresholds

        # Évaluation CPU
        cpu = metrics.get("cpu_percent", 0.0)
        alert = self._evaluate_metric("cpu", cpu, th.cpu_warn, th.cpu_crit)
        if alert:
            alerts.append(alert)

        # Évaluation Mémoire
        mem = metrics.get("mem_percent", 0.0)
        alert = self._evaluate_metric("mem", mem, th.mem_warn, th.mem_crit)
        if alert:
            alerts.append(alert)

        # Évaluation Disque
        disk = metrics.get("disk_percent", 0.0)
        alert = self._evaluate_metric("disk", disk, th.disk_warn, th.disk_crit)
        if alert:
            alerts.append(alert)

        # Évaluation Température
        temp = metrics.get("cpu_temp", 0.0)
        if temp > 0:  # Ignorer si température non disponible
            alert = self._evaluate_metric("temp", temp, th.temp_warn, th.temp_crit)
            if alert:
                # Message personnalisé pour température (°C pas %)
                alert.message = f"TEMP {temp:.0f}°C > seuil {'critique' if alert.level == 'crit' else 'avertissement'} {alert.threshold:.0f}°C"
                alerts.append(alert)

        # Évaluation WiFi RSSI (seulement si WiFi actif)
        wifi = metrics.get("wifi_rssi", 0)
        if wifi < 0:  # WiFi actif (RSSI est négatif)
            alert = self._evaluate_metric(
                "wifi", wifi, th.wifi_warn, th.wifi_crit,
                higher_is_worse=False
            )
            if alert:
                alerts.append(alert)

        # Déterminer le niveau global (pire niveau parmi les alertes)
        global_level = "nominal"
        if any(a.level == "crit" for a in alerts):
            global_level = "crit"
        elif any(a.level == "warn" for a in alerts):
            global_level = "warn"

        return {
            "global_level": global_level,
            "alerts": [a.to_dict() for a in alerts],
            "alerts_count": len(alerts),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def get_thresholds(self) -> Dict[str, Any]:
        """Retourne les seuils actuels pour debug/config."""
        return {
            "cpu_warn": self.thresholds.cpu_warn,
            "cpu_crit": self.thresholds.cpu_crit,
            "mem_warn": self.thresholds.mem_warn,
            "mem_crit": self.thresholds.mem_crit,
            "disk_warn": self.thresholds.disk_warn,
            "disk_crit": self.thresholds.disk_crit,
            "temp_warn": self.thresholds.temp_warn,
            "temp_crit": self.thresholds.temp_crit,
            "wifi_warn": self.thresholds.wifi_warn,
            "wifi_crit": self.thresholds.wifi_crit,
        }


# Instance singleton pour réutilisation
_engine: Optional[AlertsEngine] = None


def get_alerts_engine() -> AlertsEngine:
    """Retourne l'instance singleton du moteur d'alertes."""
    global _engine
    if _engine is None:
        _engine = AlertsEngine()
    return _engine


async def evaluate_alerts(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fonction utilitaire pour évaluer les alertes.
    Usage: alerts = await evaluate_alerts(metrics)
    """
    engine = get_alerts_engine()
    return await engine.evaluate(metrics)
