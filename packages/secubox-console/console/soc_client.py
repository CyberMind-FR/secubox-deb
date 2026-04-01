"""
SecuBox Console — SOC Gateway Client
Async client for communicating with SOC Gateway API.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

import httpx

logger = logging.getLogger("secubox.console.soc")

# SOC Gateway configuration
SOC_CONFIG_FILE = Path("/etc/secubox/soc-console.json")
SOC_GATEWAY_SOCK = Path("/run/secubox/soc-gateway.sock")

# Default gateway URL (can be overridden in config)
DEFAULT_GATEWAY_URL = "http://localhost/api/v1/soc-gateway"


class SOCConfig:
    """SOC connection configuration."""

    def __init__(self):
        self.enabled: bool = False
        self.gateway_url: str = DEFAULT_GATEWAY_URL
        self.use_socket: bool = True
        self.auth_token: str = ""
        self.load()

    def load(self):
        """Load configuration from file."""
        if SOC_CONFIG_FILE.exists():
            try:
                data = json.loads(SOC_CONFIG_FILE.read_text())
                self.enabled = data.get("enabled", False)
                self.gateway_url = data.get("gateway_url", DEFAULT_GATEWAY_URL)
                self.use_socket = data.get("use_socket", True)
                self.auth_token = data.get("auth_token", "")
            except Exception as e:
                logger.warning(f"Failed to load SOC config: {e}")

    def is_available(self) -> bool:
        """Check if SOC Gateway is available."""
        if self.use_socket:
            return SOC_GATEWAY_SOCK.exists()
        return bool(self.gateway_url)


# Global config
soc_config = SOCConfig()

# Shared client
_client: Optional[httpx.AsyncClient] = None


async def get_client() -> Optional[httpx.AsyncClient]:
    """Get or create HTTP client."""
    global _client

    if _client is None or _client.is_closed:
        if soc_config.use_socket and SOC_GATEWAY_SOCK.exists():
            transport = httpx.AsyncHTTPTransport(uds=str(SOC_GATEWAY_SOCK))
            _client = httpx.AsyncClient(
                transport=transport,
                base_url="http://localhost",
                timeout=30.0
            )
        elif soc_config.gateway_url:
            headers = {}
            if soc_config.auth_token:
                headers["Authorization"] = f"Bearer {soc_config.auth_token}"
            _client = httpx.AsyncClient(
                base_url=soc_config.gateway_url,
                headers=headers,
                timeout=30.0
            )
        else:
            return None

    return _client


async def close_soc_client():
    """Close the HTTP client."""
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None


async def api_get(endpoint: str) -> Optional[Dict[str, Any]]:
    """Make GET request to SOC Gateway."""
    client = await get_client()
    if not client:
        return None

    try:
        response = await client.get(endpoint)
        if response.status_code == 200:
            return response.json()
        logger.warning(f"SOC API error: {response.status_code}")
        return None
    except Exception as e:
        logger.error(f"SOC API request failed: {e}")
        return None


async def api_post(endpoint: str, data: Dict = None) -> Optional[Dict[str, Any]]:
    """Make POST request to SOC Gateway."""
    client = await get_client()
    if not client:
        return None

    try:
        response = await client.post(endpoint, json=data or {})
        if response.status_code in (200, 201):
            return response.json()
        logger.warning(f"SOC API error: {response.status_code}")
        return None
    except Exception as e:
        logger.error(f"SOC API request failed: {e}")
        return None


# ============================================================================
# SOC API Wrappers
# ============================================================================

async def get_fleet_summary() -> Optional[Dict[str, Any]]:
    """Get fleet-wide summary statistics."""
    return await api_get("/fleet/summary")


async def get_fleet_nodes(
    status: Optional[str] = None,
    region: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get list of all nodes."""
    params = []
    if status:
        params.append(f"status={status}")
    if region:
        params.append(f"region={region}")

    endpoint = "/fleet/nodes"
    if params:
        endpoint += "?" + "&".join(params)

    result = await api_get(endpoint)
    if result:
        return result.get("nodes", [])
    return []


async def get_node_detail(node_id: str) -> Optional[Dict[str, Any]]:
    """Get detailed information for a specific node."""
    return await api_get(f"/fleet/nodes/{node_id}")


async def get_alerts(
    limit: int = 50,
    source: Optional[str] = None,
    severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get unified alert stream."""
    params = [f"limit={limit}"]
    if source:
        params.append(f"source={source}")
    if severity:
        params.append(f"severity={severity}")

    endpoint = "/alerts/stream?" + "&".join(params)
    result = await api_get(endpoint)
    if result:
        return result.get("alerts", [])
    return []


async def get_correlated_threats(
    severity: Optional[str] = None,
    min_nodes: int = 2
) -> List[Dict[str, Any]]:
    """Get cross-node correlated threats."""
    params = [f"min_nodes={min_nodes}"]
    if severity:
        params.append(f"severity={severity}")

    endpoint = "/alerts/correlated?" + "&".join(params)
    result = await api_get(endpoint)
    if result:
        return result.get("threats", [])
    return []


async def get_correlation_summary() -> Optional[Dict[str, Any]]:
    """Get threat correlation summary."""
    return await api_get("/alerts/correlation-summary")


async def send_service_action(
    node_id: str,
    service: str,
    action: str
) -> Optional[Dict[str, Any]]:
    """Send service action to a remote node."""
    return await api_post(
        f"/nodes/{node_id}/services/{service}/action?action={action}"
    )


async def send_command(
    node_id: str,
    action: str,
    args: List[str] = None
) -> Optional[Dict[str, Any]]:
    """Send a command to a remote node."""
    return await api_post(
        f"/nodes/{node_id}/command",
        {"action": action, "args": args or []}
    )


async def is_soc_available() -> bool:
    """Check if SOC Gateway is reachable."""
    result = await api_get("/health")
    return result is not None and result.get("status") == "healthy"
