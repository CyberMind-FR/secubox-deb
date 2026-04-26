"""
SecuBox Eye Remote — Bluetooth Manager
Manages Bluetooth connections using bluetoothctl commands.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger(__name__)


@dataclass
class BluetoothDevice:
    """Represents a Bluetooth device."""
    address: str  # MAC address (AA:BB:CC:DD:EE:FF)
    name: str
    paired: bool
    connected: bool
    trusted: bool


@dataclass
class BluetoothStatus:
    """Bluetooth adapter status."""
    powered: bool
    discovering: bool
    pairable: bool
    adapter_name: str


class BluetoothManager:
    """
    Manages Bluetooth using bluetoothctl.

    This class wraps bluetoothctl commands to provide an async interface for
    Bluetooth device management on the Eye Remote device.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize the Bluetooth manager.

        Args:
            timeout: Subprocess timeout in seconds (default: 10)
        """
        self.timeout = timeout
        self._cached_devices: List[BluetoothDevice] = []

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

    def _parse_device_line(self, line: str) -> Optional[tuple[str, str]]:
        """
        Parse a device line from bluetoothctl output.

        Format: "Device AA:BB:CC:DD:EE:FF DeviceName"

        Args:
            line: Raw bluetoothctl device line

        Returns:
            Tuple of (address, name) or None if parsing fails
        """
        # Match "Device MAC_ADDRESS Name"
        match = re.match(r'^Device\s+([0-9A-Fa-f:]{17})\s*(.*)', line.strip())
        if match:
            address = match.group(1).upper()
            name = match.group(2).strip() if match.group(2) else ""
            return address, name
        return None

    def _parse_status_output(self, output: str) -> BluetoothStatus:
        """
        Parse bluetoothctl show output to extract adapter status.

        Args:
            output: Raw bluetoothctl show output

        Returns:
            BluetoothStatus with parsed values
        """
        powered = False
        discovering = False
        pairable = False
        adapter_name = "unknown"

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Powered:'):
                powered = 'yes' in line.lower()
            elif line.startswith('Discovering:'):
                discovering = 'yes' in line.lower()
            elif line.startswith('Pairable:'):
                pairable = 'yes' in line.lower()
            elif line.startswith('Name:') or line.startswith('Alias:'):
                # Use Name or Alias for adapter name
                parts = line.split(':', 1)
                if len(parts) > 1 and parts[1].strip():
                    adapter_name = parts[1].strip()

        return BluetoothStatus(
            powered=powered,
            discovering=discovering,
            pairable=pairable,
            adapter_name=adapter_name
        )

    async def scan(self, duration: int = 10) -> List[BluetoothDevice]:
        """
        Scan for discoverable Bluetooth devices.

        Uses: bluetoothctl scan on, wait, scan off, devices

        Args:
            duration: Scan duration in seconds (default: 10)

        Returns:
            List of detected BluetoothDevice objects
        """
        try:
            # Start scanning
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "scan", "on"
            )

            if returncode != 0:
                log.warning(f"bluetoothctl scan on failed: {stderr.decode()}")
                return []

            # Wait for scan duration
            await asyncio.sleep(duration)

            # Stop scanning
            try:
                await self._run_command("bluetoothctl", "scan", "off")
            except Exception:
                pass  # Continue even if scan off fails

            # Get discovered devices
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "devices"
            )

            if returncode != 0:
                log.warning(f"bluetoothctl devices failed: {stderr.decode()}")
                return []

            devices = []
            lines = stdout.decode().strip().split('\n')

            for line in lines:
                if not line.strip():
                    continue

                parsed = self._parse_device_line(line)
                if parsed:
                    address, name = parsed
                    devices.append(BluetoothDevice(
                        address=address,
                        name=name,
                        paired=False,
                        connected=False,
                        trusted=False
                    ))

            # Cache the results
            self._cached_devices = devices
            log.debug(f"Bluetooth scan found {len(devices)} devices")
            return devices

        except (asyncio.TimeoutError, FileNotFoundError):
            return []
        except Exception as e:
            log.error(f"Bluetooth scan error: {e}")
            return []

    async def pair(self, address: str) -> bool:
        """
        Pair with a Bluetooth device.

        Uses: bluetoothctl pair ADDRESS

        Args:
            address: MAC address of device to pair with

        Returns:
            True if pairing succeeded, False otherwise
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "pair", address
            )

            output = stdout.decode().lower() + stderr.decode().lower()

            if returncode == 0:
                log.info(f"Successfully paired with: {address}")
                return True

            # Check for already paired
            if "alreadyexists" in output or "already exists" in output:
                log.info(f"Device already paired: {address}")
                return True

            log.warning(f"Failed to pair with {address}: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            log.error(f"Pair with {address} failed: timeout or bluetoothctl not found")
            return False
        except Exception as e:
            log.error(f"Pair with {address} failed: {e}")
            return False

    async def connect(self, address: str) -> bool:
        """
        Connect to a paired Bluetooth device.

        Uses: bluetoothctl connect ADDRESS

        Args:
            address: MAC address of device to connect to

        Returns:
            True if connection succeeded, False otherwise
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "connect", address
            )

            output = stdout.decode().lower() + stderr.decode().lower()

            if returncode == 0:
                log.info(f"Successfully connected to: {address}")
                return True

            # Check for already connected
            if "already connected" in output:
                log.info(f"Device already connected: {address}")
                return True

            log.warning(f"Failed to connect to {address}: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            log.error(f"Connect to {address} failed: timeout or bluetoothctl not found")
            return False
        except Exception as e:
            log.error(f"Connect to {address} failed: {e}")
            return False

    async def disconnect(self, address: Optional[str] = None) -> bool:
        """
        Disconnect from a Bluetooth device or all devices.

        Uses: bluetoothctl disconnect [ADDRESS]

        Args:
            address: MAC address of device to disconnect from,
                     or None to disconnect all

        Returns:
            True if disconnection succeeded (or already disconnected)
        """
        try:
            if address:
                returncode, stdout, stderr = await self._run_command(
                    "bluetoothctl", "disconnect", address
                )
            else:
                returncode, stdout, stderr = await self._run_command(
                    "bluetoothctl", "disconnect"
                )

            output = stdout.decode().lower() + stderr.decode().lower()

            if returncode == 0:
                log.info(f"Disconnected from: {address or 'all devices'}")
                return True

            # Not connected is considered success
            if "not connected" in output:
                log.debug(f"Already disconnected from: {address or 'all devices'}")
                return True

            log.warning(f"Failed to disconnect: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Disconnect failed: {e}")
            return False

    async def forget(self, address: str) -> bool:
        """
        Remove a paired Bluetooth device.

        Uses: bluetoothctl remove ADDRESS

        Args:
            address: MAC address of device to remove

        Returns:
            True if device was removed successfully
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "remove", address
            )

            if returncode == 0:
                log.info(f"Removed device: {address}")
                return True

            log.warning(f"Failed to remove device {address}: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Remove device failed: {e}")
            return False

    async def list_devices(self) -> List[BluetoothDevice]:
        """
        List known/paired Bluetooth devices.

        Uses: bluetoothctl devices Paired

        Returns:
            List of paired BluetoothDevice objects
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "devices", "Paired"
            )

            if returncode != 0:
                log.warning(f"bluetoothctl devices failed: {stderr.decode()}")
                return []

            devices = []
            lines = stdout.decode().strip().split('\n')

            for line in lines:
                if not line.strip():
                    continue

                parsed = self._parse_device_line(line)
                if parsed:
                    address, name = parsed
                    devices.append(BluetoothDevice(
                        address=address,
                        name=name if name else address,
                        paired=True,
                        connected=False,
                        trusted=False
                    ))

            return devices

        except (asyncio.TimeoutError, FileNotFoundError):
            return []
        except Exception as e:
            log.error(f"List devices failed: {e}")
            return []

    async def status(self) -> BluetoothStatus:
        """
        Get Bluetooth adapter status.

        Uses: bluetoothctl show

        Returns:
            BluetoothStatus with adapter information
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "show"
            )

            if returncode != 0:
                log.warning(f"bluetoothctl show failed: {stderr.decode()}")
                return BluetoothStatus(
                    powered=False,
                    discovering=False,
                    pairable=False,
                    adapter_name="unknown"
                )

            return self._parse_status_output(stdout.decode())

        except (asyncio.TimeoutError, FileNotFoundError):
            return BluetoothStatus(
                powered=False,
                discovering=False,
                pairable=False,
                adapter_name="unknown"
            )
        except Exception as e:
            log.error(f"Status check failed: {e}")
            return BluetoothStatus(
                powered=False,
                discovering=False,
                pairable=False,
                adapter_name="unknown"
            )

    async def enable(self) -> bool:
        """
        Enable (power on) the Bluetooth adapter.

        Uses: bluetoothctl power on

        Returns:
            True if adapter was powered on successfully
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "power", "on"
            )

            if returncode == 0:
                log.info("Bluetooth adapter powered on")
                return True

            log.warning(f"Failed to power on Bluetooth: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Power on failed: {e}")
            return False

    async def disable(self) -> bool:
        """
        Disable (power off) the Bluetooth adapter.

        Uses: bluetoothctl power off

        Returns:
            True if adapter was powered off successfully
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "power", "off"
            )

            if returncode == 0:
                log.info("Bluetooth adapter powered off")
                return True

            log.warning(f"Failed to power off Bluetooth: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Power off failed: {e}")
            return False

    async def get_devices(self) -> List[BluetoothDevice]:
        """
        Get list of known devices.

        Returns cached scan results, or triggers a new list_devices if cache is empty.

        Returns:
            List of BluetoothDevice objects
        """
        if self._cached_devices:
            return self._cached_devices

        return await self.list_devices()

    async def trust(self, address: str) -> bool:
        """
        Trust a Bluetooth device (allows auto-reconnect).

        Uses: bluetoothctl trust ADDRESS

        Args:
            address: MAC address of device to trust

        Returns:
            True if device was trusted successfully
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "trust", address
            )

            if returncode == 0:
                log.info(f"Trusted device: {address}")
                return True

            log.warning(f"Failed to trust device {address}: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Trust device failed: {e}")
            return False

    async def untrust(self, address: str) -> bool:
        """
        Untrust a Bluetooth device.

        Uses: bluetoothctl untrust ADDRESS

        Args:
            address: MAC address of device to untrust

        Returns:
            True if device was untrusted successfully
        """
        try:
            returncode, stdout, stderr = await self._run_command(
                "bluetoothctl", "untrust", address
            )

            if returncode == 0:
                log.info(f"Untrusted device: {address}")
                return True

            log.warning(f"Failed to untrust device {address}: {stderr.decode()}")
            return False

        except (asyncio.TimeoutError, FileNotFoundError):
            return False
        except Exception as e:
            log.error(f"Untrust device failed: {e}")
            return False
