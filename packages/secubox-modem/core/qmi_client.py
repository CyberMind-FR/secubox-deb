# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: QMI Client
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

Wrapper for qmicli for advanced modem queries.
"""
import asyncio
import re
from typing import Optional, Dict, Any
from pathlib import Path

from secubox_core.logger import get_logger

log = get_logger("modem-qmi")


class QMIClient:
    """Client for QMI interface via qmicli."""

    def __init__(self, device: str = "/dev/cdc-wdm0"):
        self.device = device
        self._timeout = 10

    def _find_qmi_device(self) -> Optional[str]:
        """Find available QMI device."""
        candidates = [
            "/dev/cdc-wdm0",
            "/dev/cdc-wdm1",
            "/dev/qcqmi0",
        ]

        for dev in candidates:
            if Path(dev).exists():
                return dev

        return None

    async def _run_qmicli(
        self,
        *args: str,
        timeout: int = None
    ) -> Dict[str, Any]:
        """Run qmicli command."""
        if timeout is None:
            timeout = self._timeout

        device = self._find_qmi_device()
        if not device:
            return {"success": False, "error": "No QMI device found"}

        cmd = ["qmicli", "-d", device, "-p"] + list(args)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )

            output = stdout.decode().strip()
            error = stderr.decode().strip()

            if proc.returncode != 0:
                log.error("qmicli error: %s", error)
                return {"success": False, "error": error}

            return {"success": True, "output": output}

        except asyncio.TimeoutError:
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            log.error("qmicli exception: %s", e)
            return {"success": False, "error": str(e)}

    async def get_device_info(self) -> Dict[str, Any]:
        """Get device manufacturer info via DMS."""
        result = await self._run_qmicli("--dms-get-manufacturer")

        info = {}

        if result.get("success"):
            output = result.get("output", "")
            # Parse: Manufacturer: 'Quectel'
            match = re.search(r"Manufacturer:\s*'?([^'\n]+)'?", output)
            if match:
                info["manufacturer"] = match.group(1).strip()

        # Get model
        result = await self._run_qmicli("--dms-get-model")
        if result.get("success"):
            output = result.get("output", "")
            match = re.search(r"Model:\s*'?([^'\n]+)'?", output)
            if match:
                info["model"] = match.group(1).strip()

        # Get revision (firmware)
        result = await self._run_qmicli("--dms-get-revision")
        if result.get("success"):
            output = result.get("output", "")
            match = re.search(r"Revision:\s*'?([^'\n]+)'?", output)
            if match:
                info["firmware"] = match.group(1).strip()

        # Get IMEI
        result = await self._run_qmicli("--dms-get-ids")
        if result.get("success"):
            output = result.get("output", "")
            match = re.search(r"IMEI:\s*'?([^'\n]+)'?", output)
            if match:
                info["imei"] = match.group(1).strip()
            match = re.search(r"MEID:\s*'?([^'\n]+)'?", output)
            if match:
                info["meid"] = match.group(1).strip()

        return info

    async def get_signal_strength(self) -> Dict[str, Any]:
        """Get signal strength info via NAS."""
        result = await self._run_qmicli("--nas-get-signal-strength")

        if not result.get("success"):
            return {}

        output = result.get("output", "")
        signal = {}

        # Parse current RSSI
        match = re.search(r"Current:\s*\n\s*Network '([^']+)':\s*'(-?\d+) dBm'", output)
        if match:
            signal["network"] = match.group(1)
            signal["rssi"] = int(match.group(2))

        # Parse RSRP (LTE)
        match = re.search(r"RSRP:\s*'(-?\d+\.?\d*)\s*dBm'", output)
        if match:
            signal["rsrp"] = float(match.group(1))

        # Parse RSRQ
        match = re.search(r"RSRQ:\s*'(-?\d+\.?\d*)\s*dB'", output)
        if match:
            signal["rsrq"] = float(match.group(1))

        # Parse SNR
        match = re.search(r"SNR:\s*'(-?\d+\.?\d*)\s*dB'", output)
        if match:
            signal["snr"] = float(match.group(1))

        return signal

    async def get_serving_system(self) -> Dict[str, Any]:
        """Get serving system info."""
        result = await self._run_qmicli("--nas-get-serving-system")

        if not result.get("success"):
            return {}

        output = result.get("output", "")
        system = {}

        # Registration state
        match = re.search(r"Registration state:\s*'([^']+)'", output)
        if match:
            system["registration_state"] = match.group(1)

        # Data capabilities
        caps = re.findall(r"Data capabilities:\s*\n((?:\s+'[^']+'\s*\n)+)", output)
        if caps:
            system["data_capabilities"] = [
                c.strip().strip("'")
                for c in caps[0].split("\n")
                if c.strip()
            ]

        # Current PLMN
        match = re.search(r"MCC:\s*'(\d+)'\s*\n\s*MNC:\s*'(\d+)'", output)
        if match:
            system["mcc"] = match.group(1)
            system["mnc"] = match.group(2)

        # Description
        match = re.search(r"Description:\s*'([^']*)'", output)
        if match:
            system["operator"] = match.group(1)

        return system

    async def get_home_network(self) -> Dict[str, Any]:
        """Get home network info from SIM."""
        result = await self._run_qmicli("--nas-get-home-network")

        if not result.get("success"):
            return {}

        output = result.get("output", "")
        network = {}

        match = re.search(r"MCC:\s*'(\d+)'", output)
        if match:
            network["mcc"] = match.group(1)

        match = re.search(r"MNC:\s*'(\d+)'", output)
        if match:
            network["mnc"] = match.group(1)

        match = re.search(r"Description:\s*'([^']*)'", output)
        if match:
            network["description"] = match.group(1)

        return network

    async def get_cell_location(self) -> Dict[str, Any]:
        """Get cell location info."""
        result = await self._run_qmicli("--nas-get-cell-location-info")

        if not result.get("success"):
            return {}

        output = result.get("output", "")
        location = {}

        # LTE info
        match = re.search(r"Cell ID:\s*'(\d+)'", output)
        if match:
            location["cell_id"] = match.group(1)

        match = re.search(r"TAC:\s*'(\d+)'", output)
        if match:
            location["tac"] = match.group(1)

        match = re.search(r"EARFCN:\s*'(\d+)'", output)
        if match:
            location["earfcn"] = match.group(1)

        match = re.search(r"Physical Cell ID:\s*'(\d+)'", output)
        if match:
            location["pci"] = match.group(1)

        return location

    async def get_rf_band_info(self) -> Dict[str, Any]:
        """Get current RF band information."""
        result = await self._run_qmicli("--nas-get-rf-band-info")

        if not result.get("success"):
            return {}

        output = result.get("output", "")
        bands = []

        # Parse band entries
        for match in re.finditer(
            r"Radio Interface:\s*'([^']+)'\s*\n\s*Band:\s*'([^']+)'",
            output
        ):
            bands.append({
                "interface": match.group(1),
                "band": match.group(2),
            })

        return {"bands": bands}

    async def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system info."""
        result = await self._run_qmicli("--nas-get-system-info")

        if not result.get("success"):
            return {}

        output = result.get("output", "")
        info = {"output": output}

        # Parse LTE info
        if "LTE:" in output:
            lte_section = output.split("LTE:")[1].split("\n\t[")[0] if "LTE:" in output else ""
            info["lte"] = {
                "present": True,
            }

            match = re.search(r"Service status:\s*'([^']+)'", lte_section)
            if match:
                info["lte"]["service_status"] = match.group(1)

            match = re.search(r"True service status:\s*'([^']+)'", lte_section)
            if match:
                info["lte"]["true_service_status"] = match.group(1)

        return info
