#!/usr/bin/env python3
"""
SecuBox Eye Remote - Real Metrics Fetcher

Fetches actual metrics from connected SecuBox via multiple API endpoints.
Aggregates system metrics + module-specific data for dashboard display.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import asyncio
import aiohttp
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    OTG = "otg"
    WIFI = "wifi"


@dataclass
class SecuBoxMetrics:
    """Aggregated metrics from SecuBox."""

    # System metrics
    cpu_percent: float = 0.0
    mem_percent: float = 0.0
    disk_percent: float = 0.0
    load_avg_1: float = 0.0
    cpu_temp: float = 0.0
    uptime_seconds: int = 0
    hostname: str = "secubox"

    # AUTH module - authentication stats
    auth_sessions: int = 0
    auth_failed_logins: int = 0
    auth_blocked_ips: int = 0

    # WALL module - CrowdSec/firewall stats
    crowdsec_decisions: int = 0
    crowdsec_alerts_24h: int = 0
    waf_blocked_requests: int = 0
    firewall_dropped_packets: int = 0

    # MESH module - WireGuard/network
    wireguard_peers: int = 0
    wireguard_rx_bytes: int = 0
    wireguard_tx_bytes: int = 0
    wifi_rssi: int = -100

    # DPI module
    dpi_flows_active: int = 0
    dpi_protocols_detected: int = 0

    # Connection state
    connection: ConnectionState = ConnectionState.DISCONNECTED
    last_update: float = 0.0
    api_latency_ms: float = 0.0

    # Data source indicators
    has_real_system: bool = False
    has_real_auth: bool = False
    has_real_crowdsec: bool = False
    has_real_wireguard: bool = False
    has_real_dpi: bool = False


# API endpoints per module
API_ENDPOINTS = {
    'system': '/api/v1/system/metrics',
    'hub_status': '/api/v1/hub/status',
    'auth': '/api/v1/auth/stats',
    'crowdsec': '/api/v1/crowdsec/metrics',
    'wireguard': '/api/v1/wireguard/status',
    'dpi': '/api/v1/dpi/stats',
    'health': '/api/v1/health',
}

# Connection targets
OTG_BASE = "http://10.55.0.1"
WIFI_BASE = "http://secubox.local"
HTTPS_PORT = 443
HTTP_PORT = 8000


class MetricsFetcher:
    """Async metrics fetcher for SecuBox APIs."""

    def __init__(self):
        self._metrics = SecuBoxMetrics()
        self._session: Optional[aiohttp.ClientSession] = None
        self._api_base: str = ""
        self._jwt_token: str = ""
        self._last_fetch: float = 0
        self._fetch_interval: float = 2.0  # seconds
        self._connection_state = ConnectionState.DISCONNECTED

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=3, connect=1)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def probe_connection(self) -> ConnectionState:
        """Probe for SecuBox connection via OTG or WiFi."""
        session = await self._get_session()

        # Try OTG first (faster, more reliable)
        for base in [OTG_BASE, WIFI_BASE]:
            for port in [HTTP_PORT, HTTPS_PORT]:
                try:
                    url = f"{base}:{port}{API_ENDPOINTS['health']}"
                    async with session.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            self._api_base = f"{base}:{port}"
                            self._connection_state = (
                                ConnectionState.OTG if base == OTG_BASE
                                else ConnectionState.WIFI
                            )
                            return self._connection_state
                except Exception:
                    continue

        self._connection_state = ConnectionState.DISCONNECTED
        return self._connection_state

    async def _fetch_endpoint(self, endpoint_key: str) -> Optional[Dict[str, Any]]:
        """Fetch single API endpoint."""
        if not self._api_base:
            return None

        session = await self._get_session()
        url = f"{self._api_base}{API_ENDPOINTS[endpoint_key]}"

        headers = {'Accept': 'application/json'}
        if self._jwt_token:
            headers['Authorization'] = f'Bearer {self._jwt_token}'

        try:
            start = time.time()
            async with session.get(url, headers=headers, ssl=False) as resp:
                latency = (time.time() - start) * 1000
                if resp.status == 200:
                    data = await resp.json()
                    data['_latency_ms'] = latency
                    return data
        except Exception:
            pass
        return None

    async def fetch_all(self) -> SecuBoxMetrics:
        """Fetch metrics from all available endpoints."""
        now = time.time()
        if now - self._last_fetch < self._fetch_interval:
            return self._metrics

        self._last_fetch = now

        # Ensure we have a connection
        if self._connection_state == ConnectionState.DISCONNECTED:
            await self.probe_connection()

        if self._connection_state == ConnectionState.DISCONNECTED:
            self._metrics.connection = ConnectionState.DISCONNECTED
            return self._metrics

        # Fetch all endpoints concurrently
        results = await asyncio.gather(
            self._fetch_endpoint('system'),
            self._fetch_endpoint('hub_status'),
            self._fetch_endpoint('auth'),
            self._fetch_endpoint('crowdsec'),
            self._fetch_endpoint('wireguard'),
            self._fetch_endpoint('dpi'),
            return_exceptions=True
        )

        system_data, hub_data, auth_data, crowdsec_data, wg_data, dpi_data = results

        # Process system metrics
        if isinstance(system_data, dict):
            self._metrics.cpu_percent = system_data.get('cpu_percent', 0)
            self._metrics.mem_percent = system_data.get('mem_percent', 0)
            self._metrics.disk_percent = system_data.get('disk_percent', 0)
            self._metrics.load_avg_1 = system_data.get('load_avg_1', 0)
            self._metrics.cpu_temp = system_data.get('cpu_temp', 0)
            self._metrics.uptime_seconds = system_data.get('uptime_seconds', 0)
            self._metrics.hostname = system_data.get('hostname', 'secubox')
            self._metrics.wifi_rssi = system_data.get('wifi_rssi', -100)
            self._metrics.api_latency_ms = system_data.get('_latency_ms', 0)
            self._metrics.has_real_system = True

        # Process auth metrics
        if isinstance(auth_data, dict):
            self._metrics.auth_sessions = auth_data.get('active_sessions', 0)
            self._metrics.auth_failed_logins = auth_data.get('failed_logins_24h', 0)
            self._metrics.auth_blocked_ips = auth_data.get('blocked_ips', 0)
            self._metrics.has_real_auth = True

        # Process CrowdSec metrics
        if isinstance(crowdsec_data, dict):
            self._metrics.crowdsec_decisions = crowdsec_data.get('active_decisions', 0)
            self._metrics.crowdsec_alerts_24h = crowdsec_data.get('alerts_24h', 0)
            self._metrics.waf_blocked_requests = crowdsec_data.get('blocked_requests', 0)
            self._metrics.firewall_dropped_packets = crowdsec_data.get('dropped_packets', 0)
            self._metrics.has_real_crowdsec = True

        # Process WireGuard metrics
        if isinstance(wg_data, dict):
            self._metrics.wireguard_peers = wg_data.get('connected_peers', 0)
            self._metrics.wireguard_rx_bytes = wg_data.get('rx_bytes', 0)
            self._metrics.wireguard_tx_bytes = wg_data.get('tx_bytes', 0)
            self._metrics.has_real_wireguard = True

        # Process DPI metrics
        if isinstance(dpi_data, dict):
            self._metrics.dpi_flows_active = dpi_data.get('active_flows', 0)
            self._metrics.dpi_protocols_detected = dpi_data.get('protocols_detected', 0)
            self._metrics.has_real_dpi = True

        self._metrics.connection = self._connection_state
        self._metrics.last_update = now

        return self._metrics

    def get_ring_values(self) -> Dict[str, float]:
        """Get normalized 0-100 values for dashboard rings."""
        m = self._metrics

        return {
            # AUTH ring: CPU usage (authentication is CPU-intensive)
            'AUTH': min(100, max(0, m.cpu_percent)),

            # WALL ring: Memory usage (filtering uses RAM)
            'WALL': min(100, max(0, m.mem_percent)),

            # BOOT ring: Disk usage
            'BOOT': min(100, max(0, m.disk_percent)),

            # MIND ring: Load average (log scale: 0.1=10%, 1.0=50%, 10=90%)
            'MIND': self._load_to_percent(m.load_avg_1),

            # ROOT ring: Temperature (30°C=0%, 85°C=100%)
            'ROOT': self._temp_to_percent(m.cpu_temp),

            # MESH ring: WiFi signal or WireGuard activity
            'MESH': self._rssi_to_percent(m.wifi_rssi) if m.wifi_rssi > -100
                    else self._traffic_to_percent(m.wireguard_rx_bytes + m.wireguard_tx_bytes),
        }

    def get_module_details(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed metrics per module for display."""
        m = self._metrics

        return {
            'AUTH': {
                'primary': f"{m.cpu_percent:.1f}%",
                'label': 'CPU',
                'details': [
                    f"Sessions: {m.auth_sessions}",
                    f"Failed: {m.auth_failed_logins}",
                    f"Blocked: {m.auth_blocked_ips}",
                ],
                'real_data': m.has_real_auth,
            },
            'WALL': {
                'primary': f"{m.mem_percent:.1f}%",
                'label': 'MEM',
                'details': [
                    f"Decisions: {m.crowdsec_decisions}",
                    f"Alerts: {m.crowdsec_alerts_24h}",
                    f"Blocked: {m.waf_blocked_requests}",
                ],
                'real_data': m.has_real_crowdsec,
            },
            'BOOT': {
                'primary': f"{m.disk_percent:.1f}%",
                'label': 'DISK',
                'details': [
                    f"Uptime: {self._format_uptime(m.uptime_seconds)}",
                ],
                'real_data': m.has_real_system,
            },
            'MIND': {
                'primary': f"{m.load_avg_1:.2f}",
                'label': 'LOAD',
                'details': [
                    f"Host: {m.hostname}",
                ],
                'real_data': m.has_real_system,
            },
            'ROOT': {
                'primary': f"{m.cpu_temp:.1f}°C",
                'label': 'TEMP',
                'details': [
                    f"Latency: {m.api_latency_ms:.0f}ms",
                ],
                'real_data': m.has_real_system,
            },
            'MESH': {
                'primary': f"{m.wifi_rssi}dBm" if m.wifi_rssi > -100 else f"{m.wireguard_peers}",
                'label': 'WIFI' if m.wifi_rssi > -100 else 'PEERS',
                'details': [
                    f"RX: {self._format_bytes(m.wireguard_rx_bytes)}",
                    f"TX: {self._format_bytes(m.wireguard_tx_bytes)}",
                    f"Flows: {m.dpi_flows_active}",
                ],
                'real_data': m.has_real_wireguard or m.has_real_dpi,
            },
        }

    @staticmethod
    def _load_to_percent(load: float) -> float:
        """Convert load average to 0-100 scale (log)."""
        if load <= 0:
            return 5.0
        import math
        return min(95, max(5, 50 + 20 * math.log10(max(0.1, min(10, load)))))

    @staticmethod
    def _temp_to_percent(temp: float) -> float:
        """Convert temperature to 0-100 scale."""
        return min(100, max(0, (temp - 30) / 55 * 100))

    @staticmethod
    def _rssi_to_percent(rssi: int) -> float:
        """Convert RSSI (-90 to -30) to 0-100 scale."""
        return min(100, max(0, (rssi + 90) / 60 * 100))

    @staticmethod
    def _traffic_to_percent(bytes_total: int) -> float:
        """Convert traffic bytes to activity percentage."""
        if bytes_total <= 0:
            return 5.0
        import math
        # Log scale: 1KB=20%, 1MB=50%, 1GB=80%
        return min(95, max(5, 10 * math.log10(max(1, bytes_total / 100))))

    @staticmethod
    def _format_uptime(seconds: int) -> str:
        """Format uptime as human-readable."""
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        if days > 0:
            return f"{days}d {hours}h"
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

    @staticmethod
    def _format_bytes(b: int) -> str:
        """Format bytes as human-readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if b < 1024:
                return f"{b:.1f}{unit}"
            b /= 1024
        return f"{b:.1f}TB"


# Singleton instance for easy import
_fetcher: Optional[MetricsFetcher] = None


def get_fetcher() -> MetricsFetcher:
    """Get singleton MetricsFetcher instance."""
    global _fetcher
    if _fetcher is None:
        _fetcher = MetricsFetcher()
    return _fetcher


async def fetch_metrics() -> SecuBoxMetrics:
    """Convenience function to fetch metrics."""
    return await get_fetcher().fetch_all()


async def get_ring_values() -> Dict[str, float]:
    """Convenience function to get ring values."""
    await get_fetcher().fetch_all()
    return get_fetcher().get_ring_values()
