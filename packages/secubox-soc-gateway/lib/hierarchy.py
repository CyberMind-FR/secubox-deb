"""
SecuBox-Deb :: SOC Gateway Hierarchical Mode
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Manages hierarchical SOC deployment modes (edge/regional/central).
"""

import json
import hmac
import hashlib
import secrets
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict

import httpx

logger = logging.getLogger("secubox.soc-gateway.hierarchy")

# Configuration paths
CONFIG_FILE = Path("/etc/secubox/soc-hierarchy.json")
DATA_DIR = Path("/var/lib/secubox/soc-gateway")
UPSTREAM_TOKEN_FILE = DATA_DIR / "upstream_token"


class GatewayMode(str, Enum):
    """SOC Gateway deployment mode."""
    EDGE = "edge"          # Edge agent (collects metrics only)
    REGIONAL = "regional"  # Regional SOC (aggregates from edge, pushes to central)
    CENTRAL = "central"    # Central SOC (top of hierarchy, no upstream)


@dataclass
class HierarchyConfig:
    """Hierarchical deployment configuration."""
    mode: str = "central"
    region_id: str = ""
    region_name: str = ""
    upstream_url: str = ""
    upstream_token: str = ""
    upstream_interval: int = 120  # Push to central every 2 minutes
    max_depth: int = 3  # Maximum hierarchy depth
    accept_regional: bool = False  # Central: accept regional SOC connections
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HierarchyManager:
    """Manages hierarchical SOC relationships."""

    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.config_file = CONFIG_FILE
        self.upstream_token_file = data_dir / "upstream_token"

        self.config = HierarchyConfig()
        self._upstream_task: Optional[asyncio.Task] = None
        self._running: bool = False

        # Regional SOC tracking (for central mode)
        self.regional_socs: Dict[str, Dict[str, Any]] = {}
        self.regional_file = data_dir / "regional_socs.json"

        self._load_config()
        self._load_regional_socs()

    def _load_config(self):
        """Load hierarchy configuration."""
        if self.config_file.exists():
            try:
                data = json.loads(self.config_file.read_text())
                self.config = HierarchyConfig(**data)
            except Exception as e:
                logger.error(f"Failed to load hierarchy config: {e}")

        # Load upstream token if exists
        if self.upstream_token_file.exists():
            try:
                token_data = json.loads(self.upstream_token_file.read_text())
                self.config.upstream_token = token_data.get("token", "")
                if not self.config.upstream_url:
                    self.config.upstream_url = token_data.get("upstream_url", "")
            except Exception as e:
                logger.error(f"Failed to load upstream token: {e}")

    def _save_config(self):
        """Save hierarchy configuration."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        # Don't save sensitive tokens in main config
        config_data = self.config.to_dict()
        config_data.pop("upstream_token", None)

        self.config_file.write_text(json.dumps(config_data, indent=2))

    def _load_regional_socs(self):
        """Load registered regional SOCs (for central mode)."""
        if self.regional_file.exists():
            try:
                self.regional_socs = json.loads(self.regional_file.read_text())
            except Exception as e:
                logger.error(f"Failed to load regional SOCs: {e}")

    def _save_regional_socs(self):
        """Save registered regional SOCs."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.regional_file.write_text(json.dumps(self.regional_socs, indent=2))

    def get_mode(self) -> GatewayMode:
        """Get current gateway mode."""
        try:
            return GatewayMode(self.config.mode)
        except ValueError:
            return GatewayMode.CENTRAL

    def set_mode(self, mode: GatewayMode, region_id: str = "", region_name: str = ""):
        """Set gateway mode."""
        self.config.mode = mode.value
        self.config.region_id = region_id
        self.config.region_name = region_name

        if mode == GatewayMode.CENTRAL:
            self.config.accept_regional = True

        self._save_config()
        logger.info(f"Gateway mode set to: {mode.value}")

    def is_central(self) -> bool:
        """Check if running as central SOC."""
        return self.get_mode() == GatewayMode.CENTRAL

    def is_regional(self) -> bool:
        """Check if running as regional SOC."""
        return self.get_mode() == GatewayMode.REGIONAL

    def has_upstream(self) -> bool:
        """Check if this gateway has an upstream (regional mode)."""
        return self.is_regional() and bool(self.config.upstream_url)

    # =========================================================================
    # Regional SOC Registration (Central Mode)
    # =========================================================================

    def generate_regional_token(
        self,
        region_id: str,
        region_name: str,
        ttl_minutes: int = 1440  # 24 hours
    ) -> Dict[str, Any]:
        """Generate enrollment token for a regional SOC (central mode only)."""
        if not self.is_central():
            raise ValueError("Only central SOC can generate regional tokens")

        token = secrets.token_hex(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        now = datetime.utcnow()

        token_data = {
            "token_hash": token_hash,
            "region_id": region_id,
            "region_name": region_name,
            "created_at": now.isoformat() + "Z",
            "used": False
        }

        # Store in regional_socs as pending
        self.regional_socs[f"pending:{token_hash[:16]}"] = token_data
        self._save_regional_socs()

        return {
            "token": token,
            "region_id": region_id,
            "region_name": region_name
        }

    def enroll_regional_soc(
        self,
        enrollment_token: str,
        region_id: str,
        region_name: str,
        ip_address: str
    ) -> Optional[Dict[str, Any]]:
        """Enroll a regional SOC with this central (central mode only)."""
        if not self.is_central():
            return None

        token_hash = hashlib.sha256(enrollment_token.encode()).hexdigest()

        # Find and validate pending token
        pending_key = None
        for key, data in self.regional_socs.items():
            if key.startswith("pending:") and data.get("token_hash") == token_hash:
                if not data.get("used"):
                    pending_key = key
                    break

        if not pending_key:
            return None

        # Generate regional SOC token
        regional_token = secrets.token_hex(32)
        regional_token_hash = hashlib.sha256(regional_token.encode()).hexdigest()

        now = datetime.utcnow().isoformat() + "Z"

        # Create regional SOC record
        regional_data = {
            "region_id": region_id,
            "region_name": region_name,
            "token_hash": regional_token_hash,
            "ip_address": ip_address,
            "enrolled_at": now,
            "last_seen": now,
            "status": "online",
            "nodes_count": 0,
            "alerts_count": 0,
            "critical_count": 0
        }

        # Mark token as used and move to active
        del self.regional_socs[pending_key]
        self.regional_socs[region_id] = regional_data
        self._save_regional_socs()

        logger.info(f"Regional SOC enrolled: {region_id} ({region_name})")

        return {
            "regional_token": regional_token,
            "region_id": region_id,
            "enrolled_at": now
        }

    def get_regional_socs(self) -> List[Dict[str, Any]]:
        """Get all registered regional SOCs."""
        return [
            {**data, "region_id": rid}
            for rid, data in self.regional_socs.items()
            if not rid.startswith("pending:")
        ]

    def update_regional_metrics(
        self,
        region_id: str,
        metrics: Dict[str, Any]
    ) -> bool:
        """Update regional SOC metrics (central mode)."""
        if region_id not in self.regional_socs:
            return False

        self.regional_socs[region_id].update({
            "last_seen": datetime.utcnow().isoformat() + "Z",
            "status": "online",
            "nodes_count": metrics.get("nodes_online", 0),
            "nodes_total": metrics.get("nodes_total", 0),
            "alerts_count": metrics.get("alerts_count", 0),
            "critical_count": metrics.get("critical_alerts", 0),
            "correlated_threats": metrics.get("correlated_threats", []),
            "last_metrics": metrics
        })
        self._save_regional_socs()
        return True

    # =========================================================================
    # Upstream Connection (Regional Mode)
    # =========================================================================

    async def enroll_with_central(
        self,
        central_url: str,
        enrollment_token: str
    ) -> Dict[str, Any]:
        """Enroll this regional SOC with a central SOC."""
        if not self.is_regional():
            return {"status": "error", "message": "Not in regional mode"}

        payload = {
            "enrollment_token": enrollment_token,
            "region_id": self.config.region_id,
            "region_name": self.config.region_name
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{central_url}/api/v1/soc-gateway/regional/enroll",
                    json=payload
                )
                response.raise_for_status()
                result = response.json()

                if "regional_token" in result:
                    # Save upstream token
                    self.config.upstream_token = result["regional_token"]
                    self.config.upstream_url = central_url

                    token_data = {
                        "token": result["regional_token"],
                        "upstream_url": central_url,
                        "enrolled_at": datetime.utcnow().isoformat() + "Z"
                    }
                    self.data_dir.mkdir(parents=True, exist_ok=True)
                    self.upstream_token_file.write_text(json.dumps(token_data, indent=2))
                    self.upstream_token_file.chmod(0o600)

                    self._save_config()
                    logger.info(f"Enrolled with central: {central_url}")
                    return {"status": "enrolled", **result}

                return {"status": "error", "message": "No token received"}

        except httpx.HTTPStatusError as e:
            logger.error(f"Enrollment failed: {e.response.status_code}")
            return {"status": "error", "code": e.response.status_code}
        except Exception as e:
            logger.error(f"Enrollment error: {e}")
            return {"status": "error", "message": str(e)}

    def sign_payload(self, payload: str) -> str:
        """Create HMAC-SHA256 signature for upstream payload."""
        return hmac.new(
            self.config.upstream_token.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

    async def push_to_central(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Push aggregated regional data to central SOC."""
        if not self.has_upstream() or not self.config.upstream_token:
            return {"status": "not_configured"}

        try:
            payload = json.dumps(aggregated_data)
            signature = self.sign_payload(payload)

            headers = {
                "Content-Type": "application/json",
                "X-Region-ID": self.config.region_id,
                "X-Region-Signature": f"sha256={signature}",
                "X-Region-Timestamp": datetime.utcnow().isoformat() + "Z"
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.config.upstream_url}/api/v1/soc-gateway/regional/ingest",
                    content=payload,
                    headers=headers
                )
                response.raise_for_status()

                logger.debug("Pushed aggregated data to central")
                return {"status": "success"}

        except httpx.HTTPStatusError as e:
            logger.warning(f"Push to central failed: {e.response.status_code}")
            return {"status": "error", "code": e.response.status_code}
        except Exception as e:
            logger.error(f"Push to central error: {e}")
            return {"status": "error", "message": str(e)}

    async def upstream_loop(self, get_aggregated_data):
        """Background loop for pushing to central SOC."""
        self._running = True

        # Initial delay
        await asyncio.sleep(30)

        while self._running:
            try:
                if self.has_upstream():
                    data = await get_aggregated_data()
                    result = await self.push_to_central(data)

                    if result.get("status") == "error":
                        await asyncio.sleep(min(self.config.upstream_interval * 2, 600))
                    else:
                        await asyncio.sleep(self.config.upstream_interval)
                else:
                    await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Upstream loop error: {e}")
                await asyncio.sleep(120)

    def start_upstream_push(self, get_aggregated_data):
        """Start upstream push task (regional mode)."""
        if not self.is_regional():
            return False

        if self._upstream_task and not self._upstream_task.done():
            return False

        self._upstream_task = asyncio.create_task(self.upstream_loop(get_aggregated_data))
        logger.info("Upstream push started")
        return True

    def stop_upstream_push(self):
        """Stop upstream push task."""
        self._running = False
        if self._upstream_task:
            self._upstream_task.cancel()
            self._upstream_task = None
        logger.info("Upstream push stopped")

    # =========================================================================
    # Status
    # =========================================================================

    def get_status(self) -> Dict[str, Any]:
        """Get hierarchy status."""
        return {
            "mode": self.config.mode,
            "region_id": self.config.region_id or None,
            "region_name": self.config.region_name or None,
            "has_upstream": self.has_upstream(),
            "upstream_url": self.config.upstream_url if self.is_regional() else None,
            "upstream_connected": self._running if self.is_regional() else None,
            "accept_regional": self.config.accept_regional if self.is_central() else None,
            "regional_socs_count": len(self.get_regional_socs()) if self.is_central() else None
        }


# Global instance
hierarchy = HierarchyManager()
