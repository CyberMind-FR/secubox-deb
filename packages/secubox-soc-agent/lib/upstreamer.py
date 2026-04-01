"""
SecuBox-Deb :: SOC Agent Upstreamer
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Pushes collected metrics to upstream SOC gateway with HMAC signing.
"""

import hmac
import hashlib
import json
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import httpx

from .collector import collect_full_report, get_machine_id, get_hostname

logger = logging.getLogger("secubox.soc-agent.upstreamer")

# Configuration paths
CONFIG_FILE = Path("/etc/secubox/soc-agent.json")
TOKEN_FILE = Path("/var/lib/secubox/soc-agent/node_token")
DATA_DIR = Path("/var/lib/secubox/soc-agent")

# Upstreamer state
_upstream_task: Optional[asyncio.Task] = None
_running: bool = False


class UpstreamerConfig:
    """Configuration for upstream SOC connection."""

    def __init__(self):
        self.enabled: bool = False
        self.upstream_url: str = ""
        self.node_token: str = ""
        self.interval: int = 60
        self.timeout: int = 30
        self.verify_ssl: bool = True
        self.load()

    def load(self):
        """Load configuration from files."""
        if CONFIG_FILE.exists():
            try:
                config = json.loads(CONFIG_FILE.read_text())
                self.enabled = config.get("enabled", False)
                self.upstream_url = config.get("upstream_url", "")
                self.interval = config.get("interval", 60)
                self.timeout = config.get("timeout", 30)
                self.verify_ssl = config.get("verify_ssl", True)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")

        if TOKEN_FILE.exists():
            try:
                token_data = json.loads(TOKEN_FILE.read_text())
                self.node_token = token_data.get("token", "")
                if not self.upstream_url:
                    self.upstream_url = token_data.get("upstream_url", "")
                self.enabled = True
            except Exception as e:
                logger.error(f"Failed to load token: {e}")

    def save(self):
        """Save configuration."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        config = {
            "enabled": self.enabled,
            "upstream_url": self.upstream_url,
            "interval": self.interval,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl
        }
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(config, indent=2))

    def save_token(self, token: str, upstream_url: str):
        """Save node token after enrollment."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        token_data = {
            "token": token,
            "upstream_url": upstream_url,
            "enrolled_at": datetime.utcnow().isoformat() + "Z"
        }
        TOKEN_FILE.write_text(json.dumps(token_data, indent=2))
        TOKEN_FILE.chmod(0o600)

        self.node_token = token
        self.upstream_url = upstream_url
        self.enabled = True


# Global config
config = UpstreamerConfig()


def sign_payload(payload: str, secret: str) -> str:
    """Create HMAC-SHA256 signature for payload."""
    return hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


async def enroll_with_gateway(
    gateway_url: str,
    enrollment_token: str
) -> Dict[str, Any]:
    """Enroll this node with a SOC gateway using an enrollment token."""
    node_id = get_machine_id()
    hostname = get_hostname()

    payload = {
        "enrollment_token": enrollment_token,
        "node_id": node_id,
        "hostname": hostname,
        "capabilities": ["metrics", "alerts", "commands"]
    }

    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            verify=config.verify_ssl
        ) as client:
            response = await client.post(
                f"{gateway_url}/api/v1/soc-gateway/enroll",
                json=payload
            )
            response.raise_for_status()
            result = response.json()

            # Save the node token
            if "node_token" in result:
                config.save_token(
                    result["node_token"],
                    result.get("upstream_url", gateway_url)
                )
                logger.info(f"Enrolled with gateway: {gateway_url}")
                return {"status": "enrolled", **result}

            return {"status": "error", "message": "No token received"}

    except httpx.HTTPStatusError as e:
        logger.error(f"Enrollment failed: {e.response.status_code}")
        return {"status": "error", "code": e.response.status_code}
    except Exception as e:
        logger.error(f"Enrollment error: {e}")
        return {"status": "error", "message": str(e)}


async def push_metrics() -> Dict[str, Any]:
    """Push current metrics to upstream SOC."""
    if not config.enabled or not config.upstream_url or not config.node_token:
        return {"status": "not_configured"}

    try:
        # Collect metrics
        report = await collect_full_report()
        payload = json.dumps(report)

        # Sign the payload
        signature = sign_payload(payload, config.node_token)

        headers = {
            "Content-Type": "application/json",
            "X-Node-ID": report["node_id"],
            "X-Node-Signature": f"sha256={signature}",
            "X-Node-Timestamp": report["timestamp"]
        }

        async with httpx.AsyncClient(
            timeout=config.timeout,
            verify=config.verify_ssl
        ) as client:
            response = await client.post(
                f"{config.upstream_url}/api/v1/soc-gateway/ingest",
                content=payload,
                headers=headers
            )
            response.raise_for_status()

            logger.debug(f"Pushed metrics: {response.status_code}")
            return {"status": "success", "timestamp": report["timestamp"]}

    except httpx.HTTPStatusError as e:
        logger.warning(f"Push failed: {e.response.status_code}")
        return {"status": "error", "code": e.response.status_code}
    except Exception as e:
        logger.error(f"Push error: {e}")
        return {"status": "error", "message": str(e)}


async def upstreamer_loop():
    """Background loop for pushing metrics."""
    global _running
    _running = True

    # Initial delay to let system stabilize
    await asyncio.sleep(10)

    while _running:
        try:
            if config.enabled:
                result = await push_metrics()
                if result.get("status") == "error":
                    # Exponential backoff on errors
                    await asyncio.sleep(min(config.interval * 2, 300))
                else:
                    await asyncio.sleep(config.interval)
            else:
                await asyncio.sleep(30)  # Check config every 30s when disabled
                config.load()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Upstreamer error: {e}")
            await asyncio.sleep(60)


def start_upstreamer() -> bool:
    """Start the background upstreamer task."""
    global _upstream_task

    if _upstream_task and not _upstream_task.done():
        return False  # Already running

    _upstream_task = asyncio.create_task(upstreamer_loop())
    logger.info("Upstreamer started")
    return True


def stop_upstreamer():
    """Stop the background upstreamer task."""
    global _running, _upstream_task

    _running = False
    if _upstream_task:
        _upstream_task.cancel()
        _upstream_task = None
    logger.info("Upstreamer stopped")


def get_status() -> Dict[str, Any]:
    """Get upstreamer status."""
    return {
        "enabled": config.enabled,
        "running": _running and _upstream_task and not _upstream_task.done(),
        "upstream_url": config.upstream_url or None,
        "interval": config.interval,
        "enrolled": bool(config.node_token)
    }


async def test_connection() -> Dict[str, Any]:
    """Test connection to upstream SOC."""
    if not config.upstream_url:
        return {"status": "not_configured"}

    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            verify=config.verify_ssl
        ) as client:
            response = await client.get(
                f"{config.upstream_url}/api/v1/soc-gateway/health"
            )
            return {
                "status": "ok" if response.status_code == 200 else "error",
                "code": response.status_code,
                "upstream": config.upstream_url
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
