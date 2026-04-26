"""
SecuBox Eye Remote — WiFi Manager
Manages WiFi connections using nmcli commands.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger(__name__)


@dataclass
class WifiNetwork:
    """Represents a WiFi network."""
    ssid: str
    signal: int  # Signal strength 0-100
    security: str  # "open", "wpa", "wpa2", "wpa3", etc.
    connected: bool = False


@dataclass
class WifiStatus:
    """Current WiFi connection status."""
    connected: bool
    ssid: Optional[str] = None
    signal: Optional[int] = None
    ip_address: Optional[str] = None


class WifiManager:
    """
    Manages WiFi connections using nmcli.

    This class wraps nmcli commands to provide an async interface for
    WiFi network management on the Eye Remote device.
    """

    def __init__(self, interface: str = "wlan0", timeout: int = 5):
        """
        Initialize the WiFi manager.

        Args:
            interface: WiFi interface name (default: wlan0)
            timeout: Subprocess timeout in seconds (default: 5)
        """
        self.interface = interface
        self.timeout = timeout
        self._cached_networks: List[WifiNetwork] = []

    async def _run_command(self, *args: str) -> tuple[int, bytes, bytes]:
        """
        Execute a command asynchronously with timeout.

        Args:
            *args: Command and arguments

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=self.timeout
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )
            return proc.returncode or 0, stdout, stderr
        except asyncio.TimeoutError:
            log.warning(f"Command timed out: {' '.join(args)}")
            raise
        except FileNotFoundError:
            log.error(f"Command not found: {args[0]}")
            raise
        except Exception as e:
            log.error(f"Command failed: {e}")
            raise

    def _unescape_nmcli(self, value: str) -> str:
        """
        Unescape nmcli terse output escaping.

        nmcli escapes colons as \\: and backslashes as \\\\

        Args:
            value: Escaped string from nmcli

        Returns:
            Unescaped string
        """
        # Unescape backslash-colon -> colon
        result = value.replace("\\:", ":")
        # Unescape double-backslash -> single backslash
        result = result.replace("\\\\", "\\")
        return result

    def _parse_security(self, security_str: str) -> str:
        """
        Normalize security type string.

        Args:
            security_str: Security string from nmcli (e.g., "WPA2", "WPA1 WPA2", "")

        Returns:
            Normalized security type: "open", "wep", "wpa", "wpa2", "wpa3"
        """
        if not security_str or security_str.strip() == "":
            return "open"

        security_upper = security_str.upper()

        if "WPA3" in security_upper:
            return "wpa3"
        elif "WPA2" in security_upper:
            return "wpa2"
        elif "WPA1" in security_upper or "WPA" in security_upper:
            return "wpa"
        elif "WEP" in security_upper:
            return "wep"
        else:
            return "open"

    def _dbm_to_percent(self, dbm: int) -> int:
        """
        Convert dBm signal strength to percentage.

        Uses a simple linear mapping:
        -90 dBm -> 0%
        -30 dBm -> 100%

        Args:
            dbm: Signal strength in dBm (typically -90 to -30)

        Returns:
            Signal strength as percentage (0-100)
        """
        # Clamp to reasonable range
        dbm = max(-90, min(-30, dbm))
        # Linear mapping: -90 dBm = 0%, -30 dBm = 100%
        percent = int(((dbm + 90) / 60) * 100)
        return max(0, min(100, percent))

    async def scan(self) -> List[WifiNetwork]:
        """
        Scan for available WiFi networks.

        Uses: nmcli -t -f SSID,SIGNAL,SECURITY device wifi list

        Returns:
            List of detected WifiNetwork objects
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY",
                "device", "wifi", "list"
            )

            if returncode != 0:
                log.warning(f"nmcli scan failed: {stderr.decode()}")
                return []

            networks = []
            lines = stdout.decode().strip().split("\n")

            for line in lines:
                if not line.strip():
                    continue

                # nmcli terse format: SSID:SIGNAL:SECURITY
                # Handle escaped colons in SSID
                parts = self._parse_nmcli_line(line)
                if len(parts) < 3:
                    continue

                ssid = self._unescape_nmcli(parts[0])
                if not ssid:
                    # Skip hidden networks
                    continue

                try:
                    signal = int(parts[1])
                except ValueError:
                    signal = 0

                security = self._parse_security(parts[2])

                networks.append(WifiNetwork(
                    ssid=ssid,
                    signal=signal,
                    security=security,
                    connected=False
                ))

            # Cache the results
            self._cached_networks = networks
            log.debug(f"WiFi scan found {len(networks)} networks")
            return networks

        except (asyncio.TimeoutError, FileNotFoundError):
            return []
        except Exception as e:
            log.error(f"WiFi scan error: {e}")
            return []

    def _parse_nmcli_line(self, line: str) -> List[str]:
        """
        Parse a nmcli terse output line, handling escaped colons.

        Args:
            line: Raw nmcli output line

        Returns:
            List of field values
        """
        # Split on unescaped colons (colons not preceded by backslash)
        # Using a simple state machine approach
        parts = []
        current = []
        i = 0

        while i < len(line):
            char = line[i]
            if char == '\\' and i + 1 < len(line):
                # Escape sequence - include both characters
                current.append(char)
                current.append(line[i + 1])
                i += 2
            elif char == ':':
                # Unescaped colon - field separator
                parts.append(''.join(current))
                current = []
                i += 1
            else:
                current.append(char)
                i += 1

        # Don't forget the last field
        parts.append(''.join(current))
        return parts

    async def connect(self, ssid: str, password: str) -> bool:
        """
        Connect to a WiFi network.

        Uses: nmcli device wifi connect SSID password PASSWORD

        Args:
            ssid: Network SSID to connect to
            password: Network password (empty string for open networks)

        Returns:
            True if connection succeeded, False otherwise
        """
        try:
            if password:
                returncode, stdout, stderr = await self._run_command(
                    "nmcli", "device", "wifi", "connect", ssid,
                    "password", password
                )
            else:
                # Open network - no password
                returncode, stdout, stderr = await self._run_command(
                    "nmcli", "device", "wifi", "connect", ssid
                )

            if returncode == 0:
                log.info(f"Successfully connected to WiFi: {ssid}")
                return True
            else:
                log.warning(f"Failed to connect to WiFi {ssid}: {stderr.decode()}")
                return False

        except (asyncio.TimeoutError, FileNotFoundError):
            log.error(f"Connect to {ssid} failed: timeout or nmcli not found")
            return False
        except Exception as e:
            log.error(f"Connect to {ssid} failed: {e}")
            return False

    async def disconnect(self) -> bool:
        """
        Disconnect from current WiFi network.

        Uses: nmcli device disconnect wlan0

        Returns:
            True if disconnection succeeded (or already disconnected)
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "nmcli", "device", "disconnect", self.interface
            )

            if returncode == 0:
                log.info(f"Disconnected from WiFi on {self.interface}")
                return True
            else:
                # May fail if already disconnected, treat as success
                error_msg = stderr.decode()
                if "not an active connection" in error_msg.lower():
                    log.debug(f"Already disconnected from {self.interface}")
                    return True
                log.warning(f"Failed to disconnect: {error_msg}")
                return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Disconnect failed: {e}")
            return False

    async def status(self) -> WifiStatus:
        """
        Get current WiFi connection status.

        Returns:
            WifiStatus with connection details
        """
        try:
            # Check active WiFi connection
            returncode, stdout, stderr = await self._run_command(
                "nmcli", "-t", "-f", "NAME,DEVICE,TYPE,STATE",
                "connection", "show", "--active"
            )

            if returncode != 0:
                return WifiStatus(connected=False)

            # Parse connections to find WiFi
            ssid = None
            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) >= 4 and parts[2] == "802-11-wireless":
                    ssid = parts[0]
                    break

            if not ssid:
                return WifiStatus(connected=False)

            # Get IP address
            ip_address = await self._get_ip_address()

            # Get signal strength
            signal = await self._get_signal_strength()

            return WifiStatus(
                connected=True,
                ssid=ssid,
                signal=signal,
                ip_address=ip_address
            )

        except Exception as e:
            log.error(f"Status check failed: {e}")
            return WifiStatus(connected=False)

    async def _get_ip_address(self) -> Optional[str]:
        """Get IP address for the WiFi interface."""
        try:
            returncode, stdout, stderr = await self._run_command(
                "nmcli", "-t", "-f", "IP4.ADDRESS",
                "device", "show", self.interface
            )

            if returncode != 0:
                return None

            for line in stdout.decode().strip().split("\n"):
                if line.startswith("IP4.ADDRESS"):
                    # Format: IP4.ADDRESS[1]:192.168.1.50/24
                    match = re.search(r':([0-9.]+)/', line)
                    if match:
                        return match.group(1)

            return None
        except Exception:
            return None

    async def _get_signal_strength(self) -> Optional[int]:
        """Get WiFi signal strength from /proc/net/wireless."""
        try:
            returncode, stdout, stderr = await self._run_command(
                "cat", "/proc/net/wireless"
            )

            if returncode != 0:
                return None

            # Parse /proc/net/wireless
            # Format: wlan0: 0000   50.  -55.  -256        0      0      0      0     12      0
            for line in stdout.decode().strip().split("\n"):
                if self.interface in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            # Third field is signal level in dBm
                            dbm_str = parts[3].rstrip('.')
                            dbm = int(float(dbm_str))
                            return self._dbm_to_percent(dbm)
                        except ValueError:
                            pass

            return None
        except Exception:
            return None

    async def get_networks(self) -> List[WifiNetwork]:
        """
        Get list of known networks.

        Returns cached scan results, or triggers a new scan if cache is empty.

        Returns:
            List of WifiNetwork objects
        """
        if self._cached_networks:
            return self._cached_networks

        return await self.scan()

    async def forget(self, ssid: str) -> bool:
        """
        Forget a saved WiFi network.

        Uses: nmcli connection delete SSID

        Args:
            ssid: Network SSID to forget

        Returns:
            True if network was forgotten successfully
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "nmcli", "connection", "delete", ssid
            )

            if returncode == 0:
                log.info(f"Forgot WiFi network: {ssid}")
                return True
            else:
                log.warning(f"Failed to forget network {ssid}: {stderr.decode()}")
                return False

        except Exception as e:
            log.error(f"Forget network failed: {e}")
            return False

    async def get_saved_networks(self) -> List[str]:
        """
        Get list of saved WiFi network SSIDs.

        Uses: nmcli -t -f NAME,TYPE connection show

        Returns:
            List of saved network SSIDs
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "nmcli", "-t", "-f", "NAME,TYPE",
                "connection", "show"
            )

            if returncode != 0:
                return []

            networks = []
            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "802-11-wireless":
                    networks.append(parts[0])

            return networks

        except Exception as e:
            log.error(f"Get saved networks failed: {e}")
            return []
