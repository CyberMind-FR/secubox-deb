# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modem Detection
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

Auto-detect Quectel LTE/5G modems via USB and ModemManager.
"""
import asyncio
import subprocess
import re
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

from secubox_core.logger import get_logger

log = get_logger("modem-detect")


@dataclass
class ModemInfo:
    """Detected modem information."""
    index: int
    path: str
    model: str
    manufacturer: str
    equipment_id: str  # IMEI
    state: str
    power_state: str
    signal_quality: int
    access_technologies: List[str]
    primary_port: Optional[str] = None
    ports: List[str] = None
    sim_slot: int = 0

    def __post_init__(self):
        if self.ports is None:
            self.ports = []


class ModemDetector:
    """Detect and enumerate modems via ModemManager and USB."""

    # Known Quectel USB vendor IDs
    QUECTEL_VID = "2c7c"

    # Known Quectel product IDs and their models
    QUECTEL_PRODUCTS = {
        "0125": "EC25",
        "0121": "EC21",
        "0306": "EP06",
        "0512": "EM12",
        "0620": "RM500Q",
        "0800": "RM520N",
        "0801": "RG500Q",
    }

    def __init__(self):
        self._cached_modem: Optional[ModemInfo] = None
        self._cache_time: float = 0
        self._cache_ttl: float = 30.0

    async def detect_usb_modems(self) -> List[Dict[str, str]]:
        """Scan USB devices for Quectel modems."""
        modems = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "lsusb", "-d", f"{self.QUECTEL_VID}:",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)

            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue
                # Parse: Bus 001 Device 003: ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
                match = re.search(r"ID\s+([0-9a-f]{4}):([0-9a-f]{4})\s+(.+)", line, re.I)
                if match:
                    vid, pid, desc = match.groups()
                    model = self.QUECTEL_PRODUCTS.get(pid, "Unknown")
                    modems.append({
                        "vendor_id": vid,
                        "product_id": pid,
                        "description": desc.strip(),
                        "model": model,
                    })
        except Exception as e:
            log.error("USB scan error: %s", e)

        return modems

    async def get_modem_via_mmcli(self) -> Optional[ModemInfo]:
        """Get modem info from ModemManager."""
        import time

        # Check cache
        now = time.time()
        if self._cached_modem and (now - self._cache_time) < self._cache_ttl:
            return self._cached_modem

        try:
            # List modems
            proc = await asyncio.create_subprocess_exec(
                "mmcli", "-L", "-J",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            import json
            data = json.loads(stdout.decode())
            modem_list = data.get("modem-list", [])

            if not modem_list:
                log.debug("No modems found via mmcli")
                return None

            # Get first modem path
            modem_path = modem_list[0]
            modem_index = int(modem_path.split("/")[-1])

            # Get detailed info
            proc = await asyncio.create_subprocess_exec(
                "mmcli", "-m", str(modem_index), "-J",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            info = json.loads(stdout.decode())
            modem = info.get("modem", {})
            generic = modem.get("generic", {})
            _3gpp = modem.get("3gpp", {})

            # Parse ports
            ports = []
            primary_port = None
            for port_info in generic.get("ports", []):
                port_name = port_info.split()[0] if isinstance(port_info, str) else port_info
                ports.append(port_name)
                if "(at)" in str(port_info).lower() or "primary" in str(port_info).lower():
                    if not primary_port:
                        primary_port = port_name

            # Parse access technologies
            access_techs = []
            tech_str = generic.get("access-technologies", "")
            if isinstance(tech_str, list):
                access_techs = tech_str
            elif tech_str:
                access_techs = [t.strip() for t in str(tech_str).split("|")]

            modem_info = ModemInfo(
                index=modem_index,
                path=modem_path,
                model=generic.get("model", "Unknown"),
                manufacturer=generic.get("manufacturer", "Unknown"),
                equipment_id=_3gpp.get("imei", generic.get("equipment-identifier", "")),
                state=generic.get("state", "unknown"),
                power_state=generic.get("power-state", "unknown"),
                signal_quality=int(generic.get("signal-quality", {}).get("value", 0)),
                access_technologies=access_techs,
                primary_port=primary_port,
                ports=ports,
            )

            self._cached_modem = modem_info
            self._cache_time = now

            return modem_info

        except Exception as e:
            log.error("mmcli error: %s", e)
            return None

    async def find_at_port(self) -> Optional[str]:
        """Find the AT command port for the modem."""
        # Check common Quectel AT ports
        at_ports = [
            "/dev/ttyUSB2",  # Quectel EC25 AT port
            "/dev/ttyUSB1",
            "/dev/ttyUSB3",
            "/dev/cdc-wdm0",  # QMI device
        ]

        for port in at_ports:
            if Path(port).exists():
                # Try to verify it's an AT port
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "timeout", "2", "picocom", "-qrx", "1000", port,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate(input=b"AT\r\n")
                    if b"OK" in stdout:
                        return port
                except Exception:
                    pass

        # Fallback to ModemManager info
        modem = await self.get_modem_via_mmcli()
        if modem and modem.primary_port:
            port_path = f"/dev/{modem.primary_port}"
            if Path(port_path).exists():
                return port_path

        return None

    async def get_modem_summary(self) -> Dict[str, Any]:
        """Get a summary of detected modems."""
        usb_modems = await self.detect_usb_modems()
        mm_modem = await self.get_modem_via_mmcli()
        at_port = await self.find_at_port()

        return {
            "usb_devices": usb_modems,
            "modemmanager": {
                "detected": mm_modem is not None,
                "info": {
                    "index": mm_modem.index,
                    "model": mm_modem.model,
                    "manufacturer": mm_modem.manufacturer,
                    "imei": mm_modem.equipment_id,
                    "state": mm_modem.state,
                    "signal_quality": mm_modem.signal_quality,
                    "access_technologies": mm_modem.access_technologies,
                } if mm_modem else None,
            },
            "at_port": at_port,
        }
