"""
SecuBox Eye Remote — SecuBox Remote Control Client
Async HTTP client for communicating with SecuBox devices via REST API.
Provides methods for fetching metrics, alerts, module status, and issuing commands.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger(__name__)

# API Endpoints
ENDPOINT_HEALTH = "/api/v1/health"
ENDPOINT_METRICS = "/api/v1/system/metrics"
ENDPOINT_MODULES = "/api/v1/system/modules"
ENDPOINT_ALERTS = "/api/v1/system/alerts"
ENDPOINT_MODULE_RESTART = "/api/v1/system/module/{name}/restart"
ENDPOINT_LOCKDOWN = "/api/v1/security/lockdown"

# Default configuration
DEFAULT_PORT = 8000
DEFAULT_TIMEOUT = 5.0


@dataclass
class SecuBoxMetrics:
    """
    Metriques systeme d'un appareil SecuBox.

    Contient les indicateurs de performance et d'etat du systeme.
    """

    cpu_percent: float
    mem_percent: float
    disk_percent: float
    load_avg: float
    temp: Optional[float]
    wifi_rssi: Optional[int]
    uptime_seconds: int


@dataclass
class SecuBoxModule:
    """
    Etat d'un module de securite SecuBox.

    Les modules disponibles sont : AUTH, WALL, BOOT, MIND, ROOT, MESH.
    """

    name: str  # AUTH, WALL, BOOT, MIND, ROOT, MESH
    status: str  # active, inactive, error
    version: str


@dataclass
class SecuBoxAlert:
    """
    Alerte de securite provenant de SecuBox.

    Represente un evenement de securite detecte par le systeme.
    """

    id: str
    level: str  # info, warn, critical
    module: str
    message: str
    timestamp: float


class SecuBoxClient:
    """
    Client asynchrone pour l'API REST SecuBox.

    Permet de :
    - Recuperer les metriques systeme
    - Lister les modules de securite et leur etat
    - Consulter les alertes recentes
    - Redemarrer des modules individuels
    - Declencher le mode lockdown

    Example:
        async with SecuBoxClient(host="10.55.0.1", token="jwt-token") as client:
            metrics = await client.get_metrics()
            print(f"CPU: {metrics.cpu_percent}%")
    """

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        timeout: float = DEFAULT_TIMEOUT,
        token: Optional[str] = None,
    ):
        """
        Initialise le client SecuBox.

        Args:
            host: Adresse IP ou hostname du SecuBox
            port: Port de l'API REST (defaut: 8000)
            timeout: Timeout des requetes en secondes (defaut: 5.0)
            token: Token JWT pour l'authentification (optionnel)
        """
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._token = token
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SecuBoxClient":
        """Support du context manager async."""
        await self._ensure_client()
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        """Ferme le client a la sortie du context manager."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """
        Cree ou retourne le client HTTP.

        Le client est cree avec les headers d'authentification
        si un token a ete fourni.
        """
        if self._client is None:
            headers = {"Accept": "application/json"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"

            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                headers=headers,
            )
        return self._client

    async def close(self) -> None:
        """
        Ferme le client HTTP.

        Doit etre appele explicitement si le client n'est pas
        utilise comme context manager.
        """
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            log.debug("SecuBox client closed")

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Execute une requete authentifiee vers l'API SecuBox.

        Args:
            method: Methode HTTP (GET, POST, etc.)
            path: Chemin de l'endpoint (ex: /api/v1/system/metrics)
            **kwargs: Arguments supplementaires pour httpx

        Returns:
            Reponse JSON parsee

        Raises:
            httpx.HTTPStatusError: Si la reponse est une erreur HTTP
            httpx.ConnectError: Si le SecuBox est injoignable
            httpx.TimeoutException: Si la requete expire
        """
        client = await self._ensure_client()
        url = f"{self.base_url}{path}"

        log.debug("SecuBox API %s %s", method, url)

        response = await client.request(method, url, **kwargs)
        response.raise_for_status()

        return response.json()

    async def connect(self) -> bool:
        """
        Teste la connexion au SecuBox.

        Returns:
            True si le SecuBox est joignable, False sinon
        """
        try:
            client = await self._ensure_client()
            response = await client.get(f"{self.base_url}{ENDPOINT_HEALTH}")
            return response.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            log.warning("Failed to connect to SecuBox: %s", e)
            return False

    async def health_check(self) -> bool:
        """
        Verifie si le SecuBox repond.

        Effectue une requete GET sur /api/v1/health.

        Returns:
            True si le SecuBox est operationnel, False sinon
        """
        try:
            client = await self._ensure_client()
            response = await client.get(f"{self.base_url}{ENDPOINT_HEALTH}")
            return response.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            log.warning("Health check failed: %s", e)
            return False

    async def get_metrics(self) -> SecuBoxMetrics:
        """
        Recupere les metriques systeme du SecuBox.

        Returns:
            SecuBoxMetrics avec CPU, memoire, disque, temperature, etc.

        Raises:
            httpx.ConnectError: Si le SecuBox est injoignable
            httpx.TimeoutException: Si la requete expire
        """
        data = await self._request("GET", ENDPOINT_METRICS)

        return SecuBoxMetrics(
            cpu_percent=data.get("cpu_percent", 0.0),
            mem_percent=data.get("mem_percent", 0.0),
            disk_percent=data.get("disk_percent", 0.0),
            load_avg=data.get("load_avg", 0.0),
            temp=data.get("temp"),
            wifi_rssi=data.get("wifi_rssi"),
            uptime_seconds=data.get("uptime_seconds", 0),
        )

    async def get_modules(self) -> List[SecuBoxModule]:
        """
        Recupere l'etat des modules de securite.

        Returns:
            Liste de SecuBoxModule (AUTH, WALL, BOOT, MIND, ROOT, MESH)

        Raises:
            httpx.ConnectError: Si le SecuBox est injoignable
            httpx.TimeoutException: Si la requete expire
        """
        data = await self._request("GET", ENDPOINT_MODULES)
        modules_data = data.get("modules", [])

        return [
            SecuBoxModule(
                name=m.get("name", "UNKNOWN"),
                status=m.get("status", "unknown"),
                version=m.get("version", "0.0.0"),
            )
            for m in modules_data
        ]

    async def get_alerts(self, limit: int = 10) -> List[SecuBoxAlert]:
        """
        Recupere les alertes recentes.

        Args:
            limit: Nombre maximum d'alertes a retourner (defaut: 10)

        Returns:
            Liste de SecuBoxAlert triees par timestamp decroissant

        Raises:
            httpx.ConnectError: Si le SecuBox est injoignable
            httpx.TimeoutException: Si la requete expire
        """
        data = await self._request("GET", ENDPOINT_ALERTS, params={"limit": limit})
        alerts_data = data.get("alerts", [])

        return [
            SecuBoxAlert(
                id=a.get("id", ""),
                level=a.get("level", "info"),
                module=a.get("module", "UNKNOWN"),
                message=a.get("message", ""),
                timestamp=a.get("timestamp", 0.0),
            )
            for a in alerts_data
        ]

    async def restart_module(self, module_name: str) -> bool:
        """
        Redemarre un module de securite.

        Args:
            module_name: Nom du module (AUTH, WALL, BOOT, MIND, ROOT, MESH)

        Returns:
            True si le redemarrage a ete initie avec succes

        Raises:
            httpx.ConnectError: Si le SecuBox est injoignable
            httpx.TimeoutException: Si la requete expire
        """
        path = ENDPOINT_MODULE_RESTART.format(name=module_name)
        log.info("Requesting restart of module %s", module_name)

        data = await self._request("POST", path)
        return data.get("success", False)

    async def lockdown(self) -> bool:
        """
        Declenche le mode lockdown de securite.

        Le mode lockdown isole le SecuBox du reseau et bloque
        toutes les connexions entrantes sauf la console locale.

        Returns:
            True si le lockdown a ete active

        Raises:
            httpx.ConnectError: Si le SecuBox est injoignable
            httpx.TimeoutException: Si la requete expire
        """
        log.warning("Initiating security lockdown!")

        data = await self._request("POST", ENDPOINT_LOCKDOWN)
        return data.get("lockdown", False)
