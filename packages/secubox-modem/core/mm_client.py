# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ModemManager Client
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

Wrapper for ModemManager (mmcli) for connection management.
"""
import asyncio
import json
import re
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field

from secubox_core.logger import get_logger

log = get_logger("modem-mm")


@dataclass
class ConnectionConfig:
    """Connection configuration."""
    apn: str
    user: str = ""
    password: str = ""
    ip_type: str = "ipv4"
    auth: str = "none"


@dataclass
class ConnectionStatus:
    """Current connection status."""
    connected: bool
    state: str
    operator_name: str = ""
    operator_code: str = ""
    access_technology: str = ""
    signal_quality: int = 0
    ip_address: str = ""
    dns_servers: List[str] = field(default_factory=list)
    mtu: int = 0
    bearer_path: str = ""


class ModemManagerClient:
    """Client for ModemManager via mmcli subprocess calls."""

    def __init__(self, modem_index: int = 0):
        self.modem_index = modem_index
        self._connection_timeout = 60

    async def _run_mmcli(
        self,
        *args: str,
        timeout: int = 30,
        json_output: bool = True
    ) -> Dict[str, Any]:
        """Run mmcli command and return parsed output."""
        cmd = ["mmcli", "-m", str(self.modem_index)]
        if json_output:
            cmd.append("-J")
        cmd.extend(args)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )

            if proc.returncode != 0:
                error = stderr.decode().strip()
                log.error("mmcli error: %s", error)
                return {"success": False, "error": error}

            output = stdout.decode().strip()
            if json_output and output:
                try:
                    return {"success": True, "data": json.loads(output)}
                except json.JSONDecodeError:
                    return {"success": True, "output": output}

            return {"success": True, "output": output}

        except asyncio.TimeoutError:
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            log.error("mmcli exception: %s", e)
            return {"success": False, "error": str(e)}

    async def get_status(self) -> ConnectionStatus:
        """Get current modem and connection status."""
        result = await self._run_mmcli()

        if not result.get("success") or "data" not in result:
            return ConnectionStatus(
                connected=False,
                state="unknown",
            )

        modem = result["data"].get("modem", {})
        generic = modem.get("generic", {})
        _3gpp = modem.get("3gpp", {})

        state = generic.get("state", "unknown")
        connected = state in ("connected", "connecting")

        # Get access technology
        access_tech = generic.get("access-technologies", "")
        if isinstance(access_tech, list):
            access_tech = " | ".join(access_tech)

        # Get bearer info if connected
        ip_address = ""
        dns_servers = []
        mtu = 0
        bearer_path = ""

        bearers = generic.get("bearers", [])
        if bearers:
            bearer_path = bearers[0] if isinstance(bearers[0], str) else ""
            if bearer_path:
                bearer_info = await self._get_bearer_info(bearer_path)
                if bearer_info:
                    ip_address = bearer_info.get("ip_address", "")
                    dns_servers = bearer_info.get("dns_servers", [])
                    mtu = bearer_info.get("mtu", 0)

        return ConnectionStatus(
            connected=connected,
            state=state,
            operator_name=_3gpp.get("operator-name", ""),
            operator_code=_3gpp.get("operator-code", ""),
            access_technology=access_tech,
            signal_quality=int(generic.get("signal-quality", {}).get("value", 0)),
            ip_address=ip_address,
            dns_servers=dns_servers,
            mtu=mtu,
            bearer_path=bearer_path,
        )

    async def _get_bearer_info(self, bearer_path: str) -> Optional[Dict[str, Any]]:
        """Get bearer/connection info."""
        # Extract bearer index from path
        match = re.search(r"/Bearer/(\d+)$", bearer_path)
        if not match:
            return None

        bearer_index = match.group(1)

        try:
            proc = await asyncio.create_subprocess_exec(
                "mmcli", "-b", bearer_index, "-J",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            data = json.loads(stdout.decode())
            bearer = data.get("bearer", {})
            ipv4 = bearer.get("ipv4-config", {})

            return {
                "ip_address": ipv4.get("address", ""),
                "gateway": ipv4.get("gateway", ""),
                "dns_servers": ipv4.get("dns", []),
                "mtu": int(ipv4.get("mtu", 0)),
            }
        except Exception as e:
            log.debug("Bearer info error: %s", e)
            return None

    async def connect(self, config: ConnectionConfig) -> Dict[str, Any]:
        """Connect with specified APN configuration."""
        log.info("Connecting with APN: %s", config.apn)

        # Build simple-connect command
        connect_str = f"apn={config.apn}"
        if config.user:
            connect_str += f",user={config.user}"
        if config.password:
            connect_str += f",password={config.password}"
        if config.ip_type:
            connect_str += f",ip-type={config.ip_type}"
        if config.auth and config.auth != "none":
            connect_str += f",allowed-auth={config.auth}"

        result = await self._run_mmcli(
            f"--simple-connect={connect_str}",
            timeout=self._connection_timeout,
            json_output=False
        )

        if result.get("success"):
            log.info("Connection initiated successfully")
            # Wait a moment for connection to establish
            await asyncio.sleep(2)
            status = await self.get_status()
            return {
                "success": True,
                "connected": status.connected,
                "state": status.state,
                "ip_address": status.ip_address,
            }

        return result

    async def disconnect(self) -> Dict[str, Any]:
        """Disconnect the data connection."""
        log.info("Disconnecting modem")

        result = await self._run_mmcli(
            "--simple-disconnect",
            timeout=30,
            json_output=False
        )

        if result.get("success"):
            log.info("Disconnected successfully")
            return {"success": True}

        return result

    async def get_signal_info(self) -> Dict[str, Any]:
        """Get detailed signal information."""
        result = await self._run_mmcli("--signal-get")

        if not result.get("success") or "data" not in result:
            return {}

        signal = result["data"].get("modem", {}).get("signal", {})

        # Parse different signal types (LTE, 5G, etc.)
        lte = signal.get("lte", {})
        nr5g = signal.get("5g", {}) or signal.get("nr", {})

        return {
            "lte": {
                "rssi": self._parse_signal_value(lte.get("rssi")),
                "rsrp": self._parse_signal_value(lte.get("rsrp")),
                "rsrq": self._parse_signal_value(lte.get("rsrq")),
                "snr": self._parse_signal_value(lte.get("snr")),
            } if lte else None,
            "nr5g": {
                "rsrp": self._parse_signal_value(nr5g.get("rsrp")),
                "rsrq": self._parse_signal_value(nr5g.get("rsrq")),
                "snr": self._parse_signal_value(nr5g.get("snr")),
            } if nr5g else None,
        }

    def _parse_signal_value(self, value: Any) -> Optional[float]:
        """Parse signal value from mmcli output."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            # Handle strings like "-85.0 dBm" or "--"
            if value == "--" or not value:
                return None
            match = re.search(r"(-?\d+\.?\d*)", value)
            if match:
                return float(match.group(1))
        return None

    async def get_sim_info(self) -> Dict[str, Any]:
        """Get SIM card information."""
        result = await self._run_mmcli()

        if not result.get("success") or "data" not in result:
            return {}

        modem = result["data"].get("modem", {})
        generic = modem.get("generic", {})
        _3gpp = modem.get("3gpp", {})

        # Get SIM path
        sim_paths = generic.get("sim", "") or generic.get("primary-sim-slot", "")

        return {
            "imsi": _3gpp.get("imsi", ""),
            "iccid": generic.get("equipment-identifier", ""),
            "operator_name": _3gpp.get("operator-name", ""),
            "operator_code": _3gpp.get("operator-code", ""),
        }

    async def set_power_state(self, on: bool) -> Dict[str, Any]:
        """Set modem power state."""
        state = "on" if on else "off"
        return await self._run_mmcli(f"--set-power-state={state}", json_output=False)

    async def reset(self) -> Dict[str, Any]:
        """Reset the modem."""
        log.warning("Resetting modem")
        return await self._run_mmcli("--reset", timeout=60, json_output=False)

    async def factory_reset(self, code: str = "000000") -> Dict[str, Any]:
        """Factory reset the modem (requires unlock code)."""
        log.warning("Factory resetting modem")
        return await self._run_mmcli(
            f"--factory-reset={code}",
            timeout=120,
            json_output=False
        )
