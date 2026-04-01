"""
SecuBox-Deb :: Console TUI — API Client
Async HTTP client for SecuBox Unix socket APIs with caching.
"""
from __future__ import annotations
import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional
import httpx


# Unix socket paths for each module
SOCKET_BASE = Path("/run/secubox")

SOCKETS = {
    "hub": SOCKET_BASE / "hub.sock",
    "system": SOCKET_BASE / "system.sock",
    "watchdog": SOCKET_BASE / "watchdog.sock",
    "portal": SOCKET_BASE / "portal.sock",
    "netmodes": SOCKET_BASE / "netmodes.sock",
}


class CachedResponse:
    """Cached API response with TTL."""

    def __init__(self, data: Any, ttl: float = 5.0):
        self.data = data
        self.timestamp = time.monotonic()
        self.ttl = ttl

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.timestamp > self.ttl


class APIClient:
    """Async API client for SecuBox module APIs via Unix sockets."""

    def __init__(self, cache_ttl: float = 5.0):
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, CachedResponse] = {}
        self._clients: Dict[str, httpx.AsyncClient] = {}

    def _get_client(self, module: str) -> Optional[httpx.AsyncClient]:
        """Get or create async client for module socket."""
        socket_path = SOCKETS.get(module)
        if not socket_path or not socket_path.exists():
            return None

        if module not in self._clients:
            transport = httpx.AsyncHTTPTransport(uds=str(socket_path))
            self._clients[module] = httpx.AsyncClient(
                transport=transport,
                base_url="http://localhost",
                timeout=10.0
            )

        return self._clients[module]

    async def _request(
        self,
        module: str,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        use_cache: bool = True,
        cache_ttl: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Make API request to module."""
        cache_key = f"{module}:{endpoint}"

        # Check cache for GET requests
        if method == "GET" and use_cache:
            cached = self._cache.get(cache_key)
            if cached and not cached.expired:
                return cached.data

        client = self._get_client(module)
        if not client:
            return None

        try:
            if method == "GET":
                resp = await client.get(endpoint)
            elif method == "POST":
                resp = await client.post(endpoint, json=data or {})
            else:
                return None

            if resp.status_code == 200:
                result = resp.json()
                # Cache GET responses
                if method == "GET":
                    ttl = cache_ttl if cache_ttl is not None else self.cache_ttl
                    self._cache[cache_key] = CachedResponse(result, ttl)
                return result
        except Exception:
            pass

        return None

    async def close(self):
        """Close all HTTP clients."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    # ═══════════════════════════════════════════════════════════════════
    # High-level API methods
    # ═══════════════════════════════════════════════════════════════════

    async def dashboard(self) -> Dict[str, Any]:
        """Get dashboard data from hub."""
        data = await self._request("hub", "/api/v1/hub/status", cache_ttl=2.0)
        return data or {}

    async def resources(self) -> Dict[str, Any]:
        """Get system resources from hub."""
        data = await self._request("hub", "/api/v1/hub/resources", cache_ttl=2.0)
        return data or {}

    async def services(self) -> list:
        """Get service list from hub."""
        data = await self._request("hub", "/api/v1/hub/services", cache_ttl=3.0)
        return data.get("services", []) if data else []

    async def health(self) -> Dict[str, Any]:
        """Get health status from watchdog."""
        data = await self._request("watchdog", "/status", cache_ttl=5.0)
        return data or {"health": "unknown"}

    async def watchdog_summary(self) -> Dict[str, Any]:
        """Get watchdog summary."""
        data = await self._request("watchdog", "/summary", cache_ttl=5.0)
        return data or {}

    async def network_interfaces(self) -> Dict[str, Any]:
        """Get network interface classification from system."""
        data = await self._request("system", "/api/v1/system/board", cache_ttl=10.0)
        return data or {}

    async def network_mode(self) -> Dict[str, Any]:
        """Get current network mode."""
        data = await self._request("netmodes", "/api/v1/netmodes/status", cache_ttl=5.0)
        return data or {}

    async def logs(self, unit: str = "", lines: int = 50) -> list:
        """Get system logs."""
        # This would need journalctl access - will be implemented locally
        return []

    async def service_action(self, name: str, action: str) -> bool:
        """Perform action on a service (start/stop/restart/enable/disable)."""
        data = await self._request(
            "hub",
            f"/api/v1/hub/services/{name}/{action}",
            method="POST",
            use_cache=False
        )
        return data.get("success", False) if data else False

    async def uptime(self) -> str:
        """Get system uptime."""
        data = await self._request("hub", "/api/v1/hub/status", cache_ttl=2.0)
        return data.get("uptime", "unknown") if data else "unknown"

    async def board_info(self) -> Dict[str, Any]:
        """Get board detection info."""
        data = await self._request("system", "/api/v1/system/board", cache_ttl=60.0)
        return data or {}


# Global client instance
_client: Optional[APIClient] = None


def get_client() -> APIClient:
    """Get or create the global API client."""
    global _client
    if _client is None:
        _client = APIClient()
    return _client


async def close_client():
    """Close the global API client."""
    global _client
    if _client:
        await _client.close()
        _client = None
