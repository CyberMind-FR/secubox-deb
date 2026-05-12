# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: AT Command Interface
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

Serial interface for AT commands to Quectel modems.
"""
import asyncio
import re
from typing import Optional, Dict, Any, List, Callable, Awaitable
from pathlib import Path

from secubox_core.logger import get_logger

log = get_logger("modem-at")


class ATInterface:
    """Serial AT command interface for Quectel modems."""

    def __init__(self, port: str = "/dev/ttyUSB2", baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._connected = False
        self._read_timeout = 5.0
        self._subscribers: List[Callable[[str], Awaitable[None]]] = []

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(self) -> bool:
        """Open serial connection to modem."""
        if self._connected:
            return True

        if not Path(self.port).exists():
            log.error("Serial port not found: %s", self.port)
            return False

        try:
            # Use pyserial-asyncio if available
            try:
                import serial_asyncio
                self._reader, self._writer = await serial_asyncio.open_serial_connection(
                    url=self.port,
                    baudrate=self.baudrate,
                )
            except ImportError:
                # Fallback: use subprocess with picocom
                log.warning("pyserial-asyncio not available, using picocom fallback")
                return False

            self._connected = True
            log.info("Connected to %s at %d baud", self.port, self.baudrate)
            return True

        except Exception as e:
            log.error("Failed to connect to %s: %s", self.port, e)
            return False

    async def disconnect(self):
        """Close serial connection."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None
        self._connected = False
        log.info("Disconnected from %s", self.port)

    async def send_command(
        self,
        command: str,
        timeout: float = None,
        expect_ok: bool = True
    ) -> Dict[str, Any]:
        """Send AT command and wait for response."""
        if timeout is None:
            timeout = self._read_timeout

        async with self._lock:
            if not self._connected:
                if not await self.connect():
                    return {"success": False, "error": "Not connected"}

            try:
                # Ensure command ends with CR
                cmd = command.strip()
                if not cmd.endswith("\r"):
                    cmd += "\r"

                log.debug("TX: %s", cmd.strip())
                self._writer.write(cmd.encode())
                await self._writer.drain()

                # Read response
                response_lines = []
                end_time = asyncio.get_event_loop().time() + timeout

                while asyncio.get_event_loop().time() < end_time:
                    try:
                        line = await asyncio.wait_for(
                            self._reader.readline(),
                            timeout=min(1.0, end_time - asyncio.get_event_loop().time())
                        )
                        line_str = line.decode().strip()

                        if line_str:
                            log.debug("RX: %s", line_str)
                            response_lines.append(line_str)

                            # Notify subscribers
                            for sub in self._subscribers:
                                try:
                                    await sub(line_str)
                                except Exception:
                                    pass

                        # Check for final response
                        if line_str == "OK":
                            return {
                                "success": True,
                                "response": response_lines,
                                "data": "\n".join(response_lines[:-1]),
                            }
                        elif line_str.startswith("ERROR") or line_str.startswith("+CME ERROR") or line_str.startswith("+CMS ERROR"):
                            return {
                                "success": False,
                                "error": line_str,
                                "response": response_lines,
                            }

                    except asyncio.TimeoutError:
                        continue

                # Timeout without OK/ERROR
                if expect_ok:
                    return {
                        "success": False,
                        "error": "Timeout waiting for response",
                        "response": response_lines,
                    }
                else:
                    return {
                        "success": True,
                        "response": response_lines,
                        "data": "\n".join(response_lines),
                    }

            except Exception as e:
                log.error("Command error: %s", e)
                return {"success": False, "error": str(e)}

    def subscribe(self, callback: Callable[[str], Awaitable[None]]):
        """Subscribe to incoming data (for WebSocket forwarding)."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[str], Awaitable[None]]):
        """Unsubscribe from incoming data."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    # === Common AT Commands ===

    async def test(self) -> bool:
        """Test modem connection with AT command."""
        result = await self.send_command("AT")
        return result.get("success", False)

    async def get_info(self) -> Dict[str, str]:
        """Get modem information."""
        info = {}

        # Manufacturer
        result = await self.send_command("AT+GMI")
        if result.get("success"):
            info["manufacturer"] = result.get("data", "").strip()

        # Model
        result = await self.send_command("AT+GMM")
        if result.get("success"):
            info["model"] = result.get("data", "").strip()

        # Firmware version
        result = await self.send_command("AT+GMR")
        if result.get("success"):
            info["firmware"] = result.get("data", "").strip()

        # IMEI
        result = await self.send_command("AT+GSN")
        if result.get("success"):
            info["imei"] = result.get("data", "").strip()

        # IMSI
        result = await self.send_command("AT+CIMI")
        if result.get("success"):
            info["imsi"] = result.get("data", "").strip()

        return info

    async def get_signal_quality(self) -> Dict[str, Any]:
        """Get signal quality via AT+CSQ."""
        result = await self.send_command("AT+CSQ")

        if not result.get("success"):
            return {}

        data = result.get("data", "")
        # Parse: +CSQ: 18,99
        match = re.search(r"\+CSQ:\s*(\d+),(\d+)", data)
        if match:
            rssi_raw = int(match.group(1))
            ber = int(match.group(2))

            # Convert to dBm: rssi_dbm = 2 * rssi_raw - 113
            rssi_dbm = None
            if 0 <= rssi_raw <= 31:
                rssi_dbm = 2 * rssi_raw - 113

            return {
                "rssi_raw": rssi_raw,
                "rssi_dbm": rssi_dbm,
                "ber": ber if ber != 99 else None,
                "quality_percent": int(rssi_raw / 31 * 100) if rssi_raw <= 31 else None,
            }

        return {}

    async def get_extended_signal(self) -> Dict[str, Any]:
        """Get extended signal info via Quectel AT+QCSQ."""
        result = await self.send_command("AT+QCSQ")

        if not result.get("success"):
            return {}

        data = result.get("data", "")
        # Parse: +QCSQ: "LTE",-51,-85,-57,15,26
        match = re.search(r'\+QCSQ:\s*"([^"]+)",(-?\d+),(-?\d+),(-?\d+),(\d+),(\d+)', data)
        if match:
            return {
                "system_mode": match.group(1),
                "rssi": int(match.group(2)),
                "rsrp": int(match.group(3)),
                "sinr": int(match.group(4)),
                "rsrq": int(match.group(5)),
                # match.group(6) is band indicator
            }

        return {}

    async def get_network_info(self) -> Dict[str, Any]:
        """Get network registration info."""
        info = {}

        # Network registration status
        result = await self.send_command("AT+CREG?")
        if result.get("success"):
            data = result.get("data", "")
            match = re.search(r"\+CREG:\s*\d+,(\d+)", data)
            if match:
                reg_status = int(match.group(1))
                info["registration_status"] = {
                    0: "not_registered",
                    1: "registered_home",
                    2: "searching",
                    3: "denied",
                    4: "unknown",
                    5: "registered_roaming",
                }.get(reg_status, "unknown")

        # Operator info
        result = await self.send_command("AT+COPS?")
        if result.get("success"):
            data = result.get("data", "")
            match = re.search(r'\+COPS:\s*\d+,\d+,"([^"]*)",\d+', data)
            if match:
                info["operator"] = match.group(1)

        return info

    async def set_echo(self, enabled: bool) -> bool:
        """Enable/disable command echo."""
        result = await self.send_command(f"ATE{1 if enabled else 0}")
        return result.get("success", False)


class ATCommandRunner:
    """Run single AT commands via subprocess (fallback when pyserial not available)."""

    def __init__(self, port: str = "/dev/ttyUSB2", baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate

    async def run(self, command: str, timeout: int = 5) -> Dict[str, Any]:
        """Run AT command via picocom subprocess."""
        if not Path(self.port).exists():
            return {"success": False, "error": f"Port not found: {self.port}"}

        try:
            # Use picocom with timeout
            proc = await asyncio.create_subprocess_shell(
                f'echo -e "{command}\\r" | timeout {timeout} picocom -qrx 1000 -b {self.baudrate} {self.port}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)

            output = stdout.decode().strip()
            lines = [l.strip() for l in output.split("\n") if l.strip()]

            # Check for OK/ERROR
            success = "OK" in lines
            error = None
            for line in lines:
                if line.startswith("ERROR") or "CME ERROR" in line or "CMS ERROR" in line:
                    error = line
                    break

            return {
                "success": success and not error,
                "response": lines,
                "data": "\n".join([l for l in lines if l not in ("OK", command)]),
                "error": error,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
