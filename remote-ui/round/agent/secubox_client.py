"""
SecuBox Eye Remote — SecuBox HTTP Client
Async HTTP client for fetching metrics from SecuBox API.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

log = logging.getLogger(__name__)

METRICS_ENDPOINT = "/api/v1/system/metrics"
HEALTH_ENDPOINT = "/api/v1/health"
DEFAULT_TIMEOUT = 5.0


@dataclass
class SecuBoxClient:
    """
    Async HTTP client for one SecuBox.

    Handles:
    - Token-based authentication
    - Automatic fallback to secondary host
    - Connection health checking
    """
    host: str
    token: str
    fallback: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    _session: Optional[aiohttp.ClientSession] = field(default=None, repr=False)
    _using_fallback: bool = field(default=False, repr=False)

    def __post_init__(self):
        self._using_fallback = False

    @property
    def current_host(self) -> str:
        """Return the currently active host."""
        if self._using_fallback and self.fallback:
            return self.fallback
        return self.host

    @property
    def base_url(self) -> str:
        """Return base URL for API calls."""
        host = self.current_host
        if not host.startswith("http"):
            host = f"http://{host}"
        if ":" not in host.split("//")[1]:
            host = f"{host}:8000"
        return host

    def _headers(self) -> dict:
        """Return request headers with auth token."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def fetch_metrics(self) -> dict:
        """
        Fetch system metrics from SecuBox.

        Returns:
            Dict with cpu_percent, mem_percent, disk_percent, etc.

        Raises:
            Exception if both primary and fallback fail
        """
        session = await self._get_session()

        # Try primary host
        try:
            self._using_fallback = False
            url = f"{self.base_url}{METRICS_ENDPOINT}"
            log.debug("Fetching metrics from %s", url)

            async with session.get(url, headers=self._headers()) as resp:
                if resp.status == 200:
                    return await resp.json()
                log.warning("Primary host returned %d", resp.status)
        except Exception as e:
            log.warning("Primary host failed: %s", e)

        # Try fallback if available
        if self.fallback:
            try:
                self._using_fallback = True
                url = f"{self.base_url}{METRICS_ENDPOINT}"
                log.debug("Trying fallback: %s", url)

                async with session.get(url, headers=self._headers()) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    log.warning("Fallback host returned %d", resp.status)
            except Exception as e:
                log.warning("Fallback host failed: %s", e)

        # Both failed
        raise ConnectionError(f"Cannot connect to SecuBox at {self.host} or {self.fallback}")

    async def check_health(self) -> bool:
        """
        Check if SecuBox API is reachable.

        Returns:
            True if healthy
        """
        session = await self._get_session()

        for using_fallback in [False, True]:
            if using_fallback and not self.fallback:
                continue

            self._using_fallback = using_fallback
            url = f"{self.base_url}{HEALTH_ENDPOINT}"

            try:
                async with session.get(url, headers=self._headers()) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass

        return False

    @property
    def transport(self) -> str:
        """Return transport type based on current host."""
        host = self.current_host
        if "10.55.0" in host:
            return "otg"
        return "wifi"
