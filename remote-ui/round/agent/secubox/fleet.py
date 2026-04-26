"""
SecuBox Eye Remote — Fleet Aggregator for Gateway Mode
Aggregates metrics and alerts from multiple SecuBox devices for unified dashboard.

Provides fleet-wide monitoring capabilities including:
- Aggregated metrics (CPU, memory, disk averages and maximums)
- Device status overview (online/offline tracking)
- Consolidated alerts from all devices sorted by timestamp
- Background polling with configurable intervals

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from .device_manager import ConnectionState, DeviceManager, SecuBoxDevice
from .remote_control import SecuBoxClient

log = logging.getLogger(__name__)


@dataclass
class FleetMetrics:
    """
    Metriques agregees de l'ensemble des appareils SecuBox.

    Combine les statistiques de tous les appareils de la flotte
    pour fournir une vue d'ensemble dans le mode Gateway.

    Attributes:
        total_devices: Nombre total d'appareils dans la flotte
        online_devices: Nombre d'appareils en ligne
        offline_devices: Nombre d'appareils hors ligne
        avg_cpu: Utilisation CPU moyenne (pourcentage)
        avg_mem: Utilisation memoire moyenne (pourcentage)
        avg_disk: Utilisation disque moyenne (pourcentage)
        max_cpu: Utilisation CPU maximale observee
        max_mem: Utilisation memoire maximale observee
        total_alerts: Nombre total d'alertes actives
        critical_alerts: Nombre d'alertes critiques
    """

    total_devices: int
    online_devices: int
    offline_devices: int
    avg_cpu: float
    avg_mem: float
    avg_disk: float
    max_cpu: float
    max_mem: float
    total_alerts: int
    critical_alerts: int


@dataclass
class DeviceStatus:
    """
    Resume de l'etat d'un appareil SecuBox.

    Fournit une vue compacte de l'etat d'un appareil pour l'affichage
    dans la liste des appareils du mode Gateway.

    Attributes:
        device_id: Identifiant unique de l'appareil
        name: Nom d'affichage de l'appareil
        online: True si l'appareil repond, False sinon
        cpu: Utilisation CPU actuelle (None si hors ligne)
        mem: Utilisation memoire actuelle (None si hors ligne)
        alert_count: Nombre d'alertes actives sur cet appareil
        last_update: Timestamp de la derniere mise a jour (Unix epoch)
    """

    device_id: str
    name: str
    online: bool
    cpu: Optional[float]
    mem: Optional[float]
    alert_count: int
    last_update: Optional[float]


class FleetAggregator:
    """
    Agregateur de donnees pour flotte SecuBox en mode Gateway.

    Gere la collecte periodique des metriques et alertes depuis
    tous les appareils de la flotte. Fournit des statistiques
    agregees pour le dashboard unifie.

    Le polling s'execute en arriere-plan avec des intervalles configurables.
    Thread-safe grace a asyncio.Lock pour les acces concurrents.

    Example:
        async with FleetAggregator(device_manager) as aggregator:
            metrics = await aggregator.get_fleet_metrics()
            print(f"Fleet CPU avg: {metrics.avg_cpu}%")

    Attributes:
        _device_manager: DeviceManager pour la liste des appareils
        _poll_interval: Intervalle de polling en secondes
        _clients: Dictionnaire device_id -> SecuBoxClient
        _device_metrics: Cache des metriques par appareil
        _device_alerts: Cache des alertes par appareil
        _poll_task: Tache asyncio de polling en arriere-plan
        _lock: Lock asyncio pour thread-safety
    """

    def __init__(
        self,
        device_manager: DeviceManager,
        poll_interval: float = 30.0,
    ):
        """
        Initialise l'agregateur de flotte.

        Args:
            device_manager: Gestionnaire des appareils SecuBox
            poll_interval: Intervalle de polling en secondes (defaut: 30)
        """
        self._device_manager = device_manager
        self._poll_interval = poll_interval
        self._clients: Dict[str, SecuBoxClient] = {}
        self._device_metrics: Dict[str, Dict[str, Any]] = {}
        self._device_alerts: Dict[str, List[Dict[str, Any]]] = {}
        self._poll_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._running = False

        log.debug(
            "FleetAggregator initialized with poll_interval=%s",
            poll_interval
        )

    async def __aenter__(self) -> "FleetAggregator":
        """Support du context manager async."""
        await self.start()
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        """Arrete le polling a la sortie du context manager."""
        await self.stop()

    async def start(self) -> None:
        """
        Demarre le polling en arriere-plan de tous les appareils.

        Lance une tache asyncio qui interroge periodiquement chaque
        appareil de la flotte pour collecter metriques et alertes.
        """
        if self._running:
            log.warning("FleetAggregator already running")
            return

        self._running = True
        self._poll_task = asyncio.create_task(self._poll_devices())

        log.info(
            "FleetAggregator started, polling every %s seconds",
            self._poll_interval
        )

    async def stop(self) -> None:
        """
        Arrete le polling en arriere-plan.

        Annule la tache de polling et ferme toutes les connexions
        aux appareils SecuBox.
        """
        self._running = False

        if self._poll_task is not None:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
            log.debug("Poll task cancelled")

        # Fermer tous les clients
        async with self._lock:
            for device_id, client in self._clients.items():
                try:
                    await client.close()
                    log.debug("Closed client for device %s", device_id)
                except Exception as e:
                    log.warning("Error closing client %s: %s", device_id, e)
            self._clients.clear()

        log.info("FleetAggregator stopped")

    async def _poll_devices(self) -> None:
        """
        Tache de polling en arriere-plan.

        Boucle infinie qui interroge tous les appareils actifs
        a intervalles reguliers. Gere gracieusement les erreurs
        pour continuer le polling meme si un appareil est injoignable.
        """
        log.debug("Poll task started")

        while self._running:
            try:
                devices = await self._device_manager.list_devices()

                for device in devices:
                    if not device.active:
                        continue

                    try:
                        await self._ensure_client(device)
                        await self._poll_device(device)
                    except Exception as e:
                        log.warning(
                            "Error polling device %s: %s",
                            device.name, e
                        )

            except Exception as e:
                log.error("Error in poll cycle: %s", e)

            await asyncio.sleep(self._poll_interval)

        log.debug("Poll task exiting")

    async def _ensure_client(self, device: SecuBoxDevice) -> SecuBoxClient:
        """
        Cree ou retourne le client HTTP pour un appareil.

        Args:
            device: Appareil SecuBox pour lequel creer le client

        Returns:
            Client SecuBox pret a etre utilise
        """
        async with self._lock:
            if device.id not in self._clients:
                client = SecuBoxClient(
                    host=device.host,
                    port=device.port,
                )
                self._clients[device.id] = client
                log.debug(
                    "Created client for device %s (%s:%d)",
                    device.name, device.host, device.port
                )
            return self._clients[device.id]

    async def _poll_device(self, device: SecuBoxDevice) -> None:
        """
        Interroge un appareil pour ses metriques et alertes.

        Met a jour le cache local avec les donnees recues.
        Si l'appareil ne repond pas, marque l'appareil comme hors ligne.

        Args:
            device: Appareil SecuBox a interroger
        """
        client = self._clients.get(device.id)
        if client is None:
            log.warning("No client for device %s", device.id)
            return

        try:
            # Test de connectivite
            is_online = await client.health_check()

            if not is_online:
                async with self._lock:
                    self._device_metrics[device.id] = {"online": False}
                await self._device_manager.update_device_state(
                    device.id, ConnectionState.DISCONNECTED
                )
                log.debug("Device %s is offline", device.name)
                return

            # Recuperer les metriques
            metrics = await client.get_metrics()
            alerts = await client.get_alerts()

            async with self._lock:
                self._device_metrics[device.id] = {
                    "cpu_percent": metrics.cpu_percent,
                    "mem_percent": metrics.mem_percent,
                    "disk_percent": metrics.disk_percent,
                    "load_avg": metrics.load_avg,
                    "temp": metrics.temp,
                    "wifi_rssi": metrics.wifi_rssi,
                    "uptime_seconds": metrics.uptime_seconds,
                    "online": True,
                    "last_update": time.time(),
                }

                self._device_alerts[device.id] = [
                    {
                        "id": a.id,
                        "level": a.level,
                        "module": a.module,
                        "message": a.message,
                        "timestamp": a.timestamp,
                    }
                    for a in alerts
                ]

            await self._device_manager.update_device_state(
                device.id, ConnectionState.CONNECTED
            )

            log.debug(
                "Polled device %s: CPU=%.1f%% MEM=%.1f%%",
                device.name,
                metrics.cpu_percent,
                metrics.mem_percent
            )

        except Exception as e:
            log.warning("Failed to poll device %s: %s", device.name, e)
            async with self._lock:
                self._device_metrics[device.id] = {"online": False}
            await self._device_manager.update_device_state(
                device.id, ConnectionState.ERROR
            )

    async def get_fleet_metrics(self) -> FleetMetrics:
        """
        Calcule les metriques agregees de la flotte.

        Combine les donnees de tous les appareils pour produire
        des statistiques globales incluant moyennes, maximums,
        et comptages.

        Returns:
            FleetMetrics avec les statistiques agregees
        """
        async with self._lock:
            devices = await self._device_manager.list_devices()
            total_devices = len(devices)

            if total_devices == 0:
                return FleetMetrics(
                    total_devices=0,
                    online_devices=0,
                    offline_devices=0,
                    avg_cpu=0.0,
                    avg_mem=0.0,
                    avg_disk=0.0,
                    max_cpu=0.0,
                    max_mem=0.0,
                    total_alerts=0,
                    critical_alerts=0,
                )

            # Compter les appareils en ligne/hors ligne
            online_count = 0
            offline_count = 0
            cpu_values: List[float] = []
            mem_values: List[float] = []
            disk_values: List[float] = []
            total_alerts = 0
            critical_alerts = 0

            for device in devices:
                metrics = self._device_metrics.get(device.id, {})

                if metrics.get("online", False):
                    online_count += 1
                    if "cpu_percent" in metrics:
                        cpu_values.append(metrics["cpu_percent"])
                    if "mem_percent" in metrics:
                        mem_values.append(metrics["mem_percent"])
                    if "disk_percent" in metrics:
                        disk_values.append(metrics["disk_percent"])
                else:
                    offline_count += 1

                # Compter les alertes
                alerts = self._device_alerts.get(device.id, [])
                total_alerts += len(alerts)
                critical_alerts += sum(
                    1 for a in alerts if a.get("level") == "critical"
                )

            # Calculer les moyennes (eviter division par zero)
            avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0.0
            avg_mem = sum(mem_values) / len(mem_values) if mem_values else 0.0
            avg_disk = (
                sum(disk_values) / len(disk_values) if disk_values else 0.0
            )
            max_cpu = max(cpu_values) if cpu_values else 0.0
            max_mem = max(mem_values) if mem_values else 0.0

            return FleetMetrics(
                total_devices=total_devices,
                online_devices=online_count,
                offline_devices=offline_count,
                avg_cpu=avg_cpu,
                avg_mem=avg_mem,
                avg_disk=avg_disk,
                max_cpu=max_cpu,
                max_mem=max_mem,
                total_alerts=total_alerts,
                critical_alerts=critical_alerts,
            )

    async def get_fleet_status(self) -> List[DeviceStatus]:
        """
        Recupere le resume d'etat de tous les appareils.

        Retourne une liste de statuts compacts pour l'affichage
        dans la liste des appareils du dashboard Gateway.

        Returns:
            Liste de DeviceStatus pour chaque appareil de la flotte
        """
        async with self._lock:
            devices = await self._device_manager.list_devices()
            status_list: List[DeviceStatus] = []

            for device in devices:
                metrics = self._device_metrics.get(device.id, {})
                alerts = self._device_alerts.get(device.id, [])

                status = DeviceStatus(
                    device_id=device.id,
                    name=device.name,
                    online=metrics.get("online", False),
                    cpu=metrics.get("cpu_percent"),
                    mem=metrics.get("mem_percent"),
                    alert_count=len(alerts),
                    last_update=metrics.get("last_update"),
                )
                status_list.append(status)

            return status_list

    async def get_all_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Recupere les alertes agregees de tous les appareils.

        Combine les alertes de tous les appareils et les trie
        par timestamp decroissant (plus recentes en premier).

        Args:
            limit: Nombre maximum d'alertes a retourner (defaut: 50)

        Returns:
            Liste d'alertes triees par timestamp decroissant,
            chaque alerte incluant le device_id source
        """
        async with self._lock:
            all_alerts: List[Dict[str, Any]] = []

            for device_id, alerts in self._device_alerts.items():
                for alert in alerts:
                    # Ajouter le device_id source
                    alert_with_device = {**alert, "device_id": device_id}
                    all_alerts.append(alert_with_device)

            # Trier par timestamp decroissant
            all_alerts.sort(
                key=lambda a: a.get("timestamp", 0),
                reverse=True
            )

            return all_alerts[:limit]

    async def refresh_device(self, device_id: str) -> bool:
        """
        Force le rafraichissement d'un appareil specifique.

        Permet de demander une mise a jour immediate des metriques
        d'un appareil sans attendre le prochain cycle de polling.

        Args:
            device_id: Identifiant de l'appareil a rafraichir

        Returns:
            True si l'appareil a ete rafraichi, False si non trouve
        """
        device = await self._device_manager.get_device(device_id)

        if device is None:
            log.warning("Cannot refresh device %s: not found", device_id)
            return False

        try:
            await self._ensure_client(device)
            await self._poll_device(device)
            log.info("Refreshed device %s", device.name)
            return True

        except Exception as e:
            log.error("Failed to refresh device %s: %s", device_id, e)
            return False
