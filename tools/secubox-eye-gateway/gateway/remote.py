"""
SecuBox Eye Gateway — Remote device connection.

Provides non-blocking interface to Eye Remote devices via SSH.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of a remote command execution."""

    command: str
    stdout: str
    stderr: str
    return_code: int
    duration_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "success": self.return_code == 0,
        }


class EyeRemoteConnection:
    """Non-blocking SSH connection to Eye Remote device."""

    # Known Eye Remote IP addresses
    OTG_IP = "10.55.0.2"
    WIFI_FALLBACK = "secubox-round.local"

    def __init__(
        self,
        host: str = OTG_IP,
        user: str = "pi",
        port: int = 22,
        timeout: float = 5.0,
    ) -> None:
        """Initialize connection parameters.

        Args:
            host: Remote host IP or hostname
            user: SSH username
            port: SSH port
            timeout: Command timeout in seconds
        """
        self.host = host
        self.user = user
        self.port = port
        self.timeout = timeout
        self._connected = False
        self._device_info: Optional[Dict[str, Any]] = None

    @property
    def ssh_target(self) -> str:
        """SSH target string (user@host)."""
        return f"{self.user}@{self.host}"

    def _ssh_cmd(self, command: str) -> List[str]:
        """Build SSH command array.

        Args:
            command: Command to execute remotely

        Returns:
            Full SSH command as list
        """
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=3",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(self.port),
            self.ssh_target,
            command,
        ]

    async def check_connection(self) -> bool:
        """Check if device is reachable.

        Returns:
            True if SSH connection succeeds
        """
        try:
            result = await self.execute("echo ok", timeout=3.0)
            self._connected = result.return_code == 0 and "ok" in result.stdout
            return self._connected
        except Exception as e:
            logger.warning(f"Connection check failed: {e}")
            self._connected = False
            return False

    async def execute(
        self,
        command: str,
        timeout: Optional[float] = None,
    ) -> CommandResult:
        """Execute command on remote device.

        Args:
            command: Shell command to execute
            timeout: Override default timeout

        Returns:
            CommandResult with output and status
        """
        timeout = timeout or self.timeout
        ssh_cmd = self._ssh_cmd(command)

        start = asyncio.get_event_loop().time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            duration = (asyncio.get_event_loop().time() - start) * 1000

            return CommandResult(
                command=command,
                stdout=stdout.decode("utf-8", errors="replace").strip(),
                stderr=stderr.decode("utf-8", errors="replace").strip(),
                return_code=proc.returncode or 0,
                duration_ms=round(duration, 2),
            )

        except asyncio.TimeoutError:
            duration = (asyncio.get_event_loop().time() - start) * 1000
            return CommandResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                duration_ms=round(duration, 2),
            )
        except Exception as e:
            duration = (asyncio.get_event_loop().time() - start) * 1000
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-2,
                duration_ms=round(duration, 2),
            )

    async def get_device_info(self) -> Dict[str, Any]:
        """Get device information.

        Returns:
            Device info dictionary
        """
        if self._device_info:
            return self._device_info

        # Gather device info with parallel commands
        commands = {
            "hostname": "hostname",
            "kernel": "uname -r",
            "uptime": "cat /proc/uptime | cut -d' ' -f1",
            "cpu_model": "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2",
            "mem_total": "grep MemTotal /proc/meminfo | awk '{print $2}'",
            "ip_usb0": "ip -4 addr show usb0 2>/dev/null | grep inet | awk '{print $2}'",
        }

        results = {}
        for key, cmd in commands.items():
            result = await self.execute(cmd, timeout=3.0)
            results[key] = result.stdout if result.return_code == 0 else ""

        self._device_info = {
            "hostname": results.get("hostname", "unknown"),
            "kernel": results.get("kernel", ""),
            "uptime_seconds": float(results.get("uptime", "0") or "0"),
            "cpu_model": results.get("cpu_model", "").strip(),
            "memory_kb": int(results.get("mem_total", "0") or "0"),
            "ip_address": results.get("ip_usb0", "").split("/")[0],
            "connected": self._connected,
        }

        return self._device_info

    async def get_metrics(self) -> Dict[str, Any]:
        """Get system metrics from device.

        Returns:
            Metrics dictionary
        """
        cmd = """python3 -c "
import json, os
stat = os.statvfs('/')
mem = {}
with open('/proc/meminfo') as f:
    for line in f:
        parts = line.split()
        if len(parts) >= 2:
            mem[parts[0].rstrip(':')] = int(parts[1])
temp = 0
try:
    with open('/sys/class/thermal/thermal_zone0/temp') as f:
        temp = int(f.read()) / 1000
except: pass
load = os.getloadavg()
print(json.dumps({
    'cpu_percent': round(load[0] * 100 / os.cpu_count(), 1),
    'memory_percent': round(100 * (1 - mem.get('MemAvailable', 0) / mem.get('MemTotal', 1)), 1),
    'disk_percent': round(100 * (1 - stat.f_bavail / stat.f_blocks), 1),
    'temperature': round(temp, 1),
    'load_avg': round(load[0], 2),
}))
"
"""
        result = await self.execute(cmd.strip(), timeout=5.0)

        if result.return_code == 0:
            try:
                import json
                return json.loads(result.stdout)
            except Exception:
                pass

        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "temperature": 0,
            "load_avg": 0,
            "error": result.stderr or "Failed to get metrics",
        }

    async def get_services_status(self) -> Dict[str, str]:
        """Get status of SecuBox services.

        Returns:
            Dictionary of service names to status
        """
        services = [
            "secubox-eye-agent",
            "secubox-eye-gadget",
            "hyperpixel2r-init",
            "pigpiod",
        ]

        results = {}
        for svc in services:
            result = await self.execute(
                f"systemctl is-active {svc} 2>/dev/null || echo unknown",
                timeout=3.0,
            )
            results[svc] = result.stdout.strip() if result.return_code == 0 else "error"

        return results

    async def restart_service(self, service: str) -> CommandResult:
        """Restart a systemd service.

        Args:
            service: Service name (without .service suffix)

        Returns:
            Command result
        """
        return await self.execute(
            f"sudo systemctl restart {service}",
            timeout=10.0,
        )

    async def capture_screenshot(self) -> Optional[bytes]:
        """Capture framebuffer screenshot.

        Returns:
            PNG image bytes or None on failure
        """
        # Capture framebuffer and convert to PNG
        cmd = """
cat /dev/fb0 | python3 -c "
import sys
from PIL import Image
data = sys.stdin.buffer.read()
# HyperPixel 2.1 Round: 480x480 RGB888
img = Image.frombytes('RGB', (480, 480), data[:480*480*3])
img.save(sys.stdout.buffer, 'PNG')
" 2>/dev/null
"""
        result = await self.execute(cmd.strip(), timeout=10.0)

        if result.return_code == 0 and result.stdout:
            # Note: stdout is text, need binary transfer
            # For now, return None and suggest SCP
            return None

        return None

    async def get_journal_logs(
        self,
        unit: str = "secubox-eye-agent",
        lines: int = 50,
    ) -> str:
        """Get recent journal logs.

        Args:
            unit: Systemd unit to filter
            lines: Number of lines to return

        Returns:
            Log output
        """
        result = await self.execute(
            f"journalctl -u {unit} -n {lines} --no-pager",
            timeout=5.0,
        )
        return result.stdout if result.return_code == 0 else result.stderr


# Global connection instance
_connection: Optional[EyeRemoteConnection] = None


def get_connection() -> EyeRemoteConnection:
    """Get or create the global connection."""
    global _connection
    if _connection is None:
        _connection = EyeRemoteConnection()
    return _connection


def set_connection(conn: EyeRemoteConnection) -> None:
    """Set the global connection."""
    global _connection
    _connection = conn
