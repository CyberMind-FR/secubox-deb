"""
LocalAPI for Pi Zero local settings and information.

Provides system information endpoints for the Eye Remote touchscreen controller.
CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import os
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from action_executor import ActionResult


VERSION = "2.1.0"


class LocalAPI:
    """Local API for Pi Zero system information."""

    async def execute(self, method: str, param: Optional[str]) -> ActionResult:
        """
        Execute a local API method.

        Args:
            method: Method name (about, system_info, storage, etc.)
            param: Optional parameter

        Returns:
            ActionResult with method execution result
        """
        handlers = {
            "about": self._about,
            "system_info": self._system_info,
            "storage": self._storage,
            "memory": self._memory,
            "cpu_info": self._cpu_info,
            "net_status": self._net_status,
            "brightness": self._brightness,
            "logs": self._logs,
        }

        handler = handlers.get(method)
        if not handler:
            return ActionResult(
                success=False,
                message=f"Unknown local method: {method}",
                data=None,
            )

        try:
            return await handler(param)
        except Exception as e:
            return ActionResult(
                success=False, message=f"Local API error: {e}", data=None
            )

    async def _about(self, param: Optional[str]) -> ActionResult:
        """Return version and about information."""
        return ActionResult(
            success=True,
            message=f"Eye Remote v{VERSION}",
            data={
                "version": VERSION,
                "name": "SecuBox Eye Remote",
                "hardware": "RPi Zero W",
                "display": "HyperPixel 2.1 Round",
            },
        )

    async def _system_info(self, param: Optional[str]) -> ActionResult:
        """Return system information."""
        hostname = socket.gethostname()
        uptime_seconds = self._get_uptime()

        return ActionResult(
            success=True,
            message=f"System: {hostname}",
            data={
                "hostname": hostname,
                "uptime_seconds": uptime_seconds,
                "uptime_formatted": self._format_uptime(uptime_seconds),
            },
        )

    async def _storage(self, param: Optional[str]) -> ActionResult:
        """Return storage/disk usage."""
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        percent = int((used / total) * 100) if total > 0 else 0

        return ActionResult(
            success=True,
            message=f"Storage: {percent}% used",
            data={
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "percent": percent,
            },
        )

    async def _memory(self, param: Optional[str]) -> ActionResult:
        """Return memory usage from /proc/meminfo."""
        try:
            meminfo = Path("/proc/meminfo").read_text()
            mem_total = 0
            mem_available = 0

            for line in meminfo.splitlines():
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) * 1024  # KB to bytes
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1]) * 1024

            mem_used = mem_total - mem_available
            percent = int((mem_used / mem_total) * 100) if mem_total > 0 else 0

            return ActionResult(
                success=True,
                message=f"Memory: {percent}% used",
                data={
                    "total_bytes": mem_total,
                    "used_bytes": mem_used,
                    "available_bytes": mem_available,
                    "percent": percent,
                },
            )
        except Exception as e:
            return ActionResult(success=False, message=f"Memory read error: {e}")

    async def _cpu_info(self, param: Optional[str]) -> ActionResult:
        """Return CPU temperature and load."""
        temp = self._get_cpu_temp()
        load = os.getloadavg()[0]

        return ActionResult(
            success=True,
            message=f"CPU: {temp}°C, Load: {load:.2f}",
            data={
                "temp_celsius": temp,
                "load_avg_1": load,
            },
        )

    async def _net_status(self, param: Optional[str]) -> ActionResult:
        """Return network status."""
        interfaces = self._get_network_interfaces()

        return ActionResult(
            success=True,
            message=f"Network: {len(interfaces)} interface(s)",
            data={"interfaces": interfaces},
        )

    async def _brightness(self, param: Optional[str]) -> ActionResult:
        """Get or set display brightness."""
        if param:
            # Set brightness (not implemented yet)
            return ActionResult(
                success=False, message="Brightness control not implemented"
            )
        else:
            # Get brightness
            return ActionResult(
                success=True,
                message="Brightness: 100%",
                data={"percent": 100},
            )

    async def _logs(self, param: Optional[str]) -> ActionResult:
        """Return recent system logs."""
        try:
            result = subprocess.run(
                ["journalctl", "-n", "10", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            logs = result.stdout.strip().splitlines()

            return ActionResult(
                success=True,
                message=f"Logs: {len(logs)} entries",
                data={"logs": logs},
            )
        except Exception as e:
            return ActionResult(success=False, message=f"Log read error: {e}")

    def _get_uptime(self) -> int:
        """Get system uptime in seconds."""
        try:
            uptime_str = Path("/proc/uptime").read_text().split()[0]
            return int(float(uptime_str))
        except Exception:
            return 0

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime seconds as human-readable string."""
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h{minutes:02d}"

    def _get_cpu_temp(self) -> float:
        """Get CPU temperature in Celsius."""
        try:
            # Try thermal zone first
            temp_path = Path("/sys/class/thermal/thermal_zone0/temp")
            if temp_path.exists():
                temp_millis = int(temp_path.read_text().strip())
                return round(temp_millis / 1000.0, 1)
        except Exception:
            pass

        # Fallback to vcgencmd on RPi
        try:
            result = subprocess.run(
                ["vcgencmd", "measure_temp"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            # Output: temp=42.8'C
            temp_str = result.stdout.strip().split("=")[1].split("'")[0]
            return round(float(temp_str), 1)
        except Exception:
            return 0.0

    def _get_network_interfaces(self) -> list[dict[str, Any]]:
        """Get network interface information."""
        interfaces = []

        try:
            # Read /proc/net/dev
            net_dev = Path("/proc/net/dev").read_text()

            for line in net_dev.splitlines()[2:]:  # Skip header lines
                if ":" not in line:
                    continue

                iface_name = line.split(":")[0].strip()

                # Skip loopback
                if iface_name == "lo":
                    continue

                interfaces.append(
                    {
                        "name": iface_name,
                        "state": "up",  # Simplified - could check /sys/class/net
                    }
                )
        except Exception:
            pass

        return interfaces
