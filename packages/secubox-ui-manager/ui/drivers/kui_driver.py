"""
SecuBox UI Manager - KUI Driver (Kiosk UI)
==========================================

Manages X11 + Chromium kiosk mode.

Responsibilities:
    - Generate xorg.conf.d for hypervisor
    - Start X11 on specified VT
    - Launch Chromium in kiosk mode
    - Monitor X11/Chromium health
"""

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..lib.debug import get_logger
from ..lib.hypervisor import HypervisorDetector, GraphicsConfig
from ..lib.display import DisplayDetector

log = get_logger("kui")


class KUIDriver:
    """
    KUI (Kiosk UI) driver for X11 + Chromium.

    Usage:
        driver = KUIDriver()
        if driver.can_start():
            success = driver.start()
            if not success:
                error = driver.get_error()
    """

    # Configuration
    KIOSK_USER = "kiosk"
    KIOSK_HOME = "/home/kiosk"
    KIOSK_URL = "http://127.0.0.1:8080/"
    XORG_CONF_DIR = Path("/etc/X11/xorg.conf.d")
    STARTUP_TIMEOUT = 30  # seconds

    def __init__(self):
        self._hypervisor = HypervisorDetector()
        self._display = DisplayDetector()
        self._config: Optional[GraphicsConfig] = None
        self._x_pid: Optional[int] = None
        self._chromium_pid: Optional[int] = None
        self._error: str = ""
        self._vt: int = 7

    def can_start(self) -> bool:
        """Check if KUI mode can be started."""
        # Check for display capabilities
        if not self._display.can_start_kui():
            self._error = "No graphics capability detected"
            return False

        # Check for xinit/startx
        if not (Path("/usr/bin/xinit").exists() or Path("/usr/bin/startx").exists()):
            self._error = "xinit/startx not installed"
            return False

        # Check for Chromium
        if not Path("/usr/bin/chromium").exists():
            self._error = "Chromium not installed"
            return False

        # Check for kiosk user
        try:
            import pwd
            pwd.getpwnam(self.KIOSK_USER)
        except KeyError:
            self._error = f"User {self.KIOSK_USER} does not exist"
            return False

        return True

    def configure(self) -> bool:
        """Configure X11 for the detected hypervisor."""
        try:
            # Detect hypervisor and get config
            info = self._hypervisor.detect()
            self._config = info.config

            log.info(
                "Hypervisor: %s, Driver: %s, 3D: %s",
                info.type,
                self._config.driver,
                not self._config.disable_3d,
            )

            # Write xorg.conf.d
            self.XORG_CONF_DIR.mkdir(parents=True, exist_ok=True)
            conf_path = self.XORG_CONF_DIR / "10-secubox.conf"
            self._hypervisor.write_xorg_conf(self._config, str(conf_path))

            # Find free VT
            self._vt = self._display.find_free_vt()
            self._config.vt = self._vt

            return True

        except Exception as e:
            self._error = f"Configuration failed: {e}"
            log.error(self._error)
            return False

    def start(self) -> bool:
        """
        Start KUI mode.

        Returns:
            True if started successfully
        """
        log.info("Starting KUI mode")

        # Configure first
        if not self.configure():
            return False

        try:
            # Create .xsession for kiosk user
            self._create_xsession()

            # Start X11 via xinit
            if not self._start_x11():
                return False

            # Wait for DISPLAY
            if not self._wait_for_display():
                self._error = "X11 failed to start within timeout"
                self.stop()
                return False

            # Launch Chromium
            if not self._launch_chromium():
                self._error = "Chromium failed to start"
                self.stop()
                return False

            log.info("KUI mode started successfully on VT%d", self._vt)
            return True

        except Exception as e:
            self._error = str(e)
            log.error("KUI start failed: %s", e)
            self.stop()
            return False

    def _create_xsession(self):
        """Create .xsession file for kiosk user."""
        xsession_content = f"""#!/bin/bash
# SecuBox KUI - X Session
set -e

# Disable screen blanking
xset -dpms
xset s off
xset s noblank

# Hide cursor after 3 seconds
unclutter -idle 3 -root &

# Wait for window manager (if any)
sleep 1

# Launch Chromium in kiosk mode
exec chromium \\
    --kiosk \\
    --noerrdialogs \\
    --disable-infobars \\
    --disable-session-crashed-bubble \\
    --disable-restore-session-state \\
    --disable-translate \\
    --no-first-run \\
    --start-maximized \\
    --disable-gpu \\
    "{self.KIOSK_URL}"
"""
        xsession_path = Path(self.KIOSK_HOME) / ".xsession"
        xsession_path.write_text(xsession_content)
        xsession_path.chmod(0o755)

        # Ensure ownership
        import pwd
        pw = pwd.getpwnam(self.KIOSK_USER)
        os.chown(xsession_path, pw.pw_uid, pw.pw_gid)

        log.debug("Created %s", xsession_path)

    def _start_x11(self) -> bool:
        """Start X11 server."""
        log.info("Starting X11 on VT%d", self._vt)

        # Build xinit command
        xsession = Path(self.KIOSK_HOME) / ".xsession"

        # Run xinit as kiosk user
        cmd = [
            "su", "-l", self.KIOSK_USER, "-c",
            f"xinit {xsession} -- :0 vt{self._vt} -nolisten tcp -keeptty"
        ]

        try:
            # Start in background
            env = os.environ.copy()
            env["XDG_RUNTIME_DIR"] = f"/run/user/{self._get_kiosk_uid()}"

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
            self._x_pid = proc.pid
            log.debug("xinit started, PID: %d", self._x_pid)
            return True

        except Exception as e:
            self._error = f"Failed to start X11: {e}"
            log.error(self._error)
            return False

    def _get_kiosk_uid(self) -> int:
        """Get UID of kiosk user."""
        import pwd
        return pwd.getpwnam(self.KIOSK_USER).pw_uid

    def _wait_for_display(self) -> bool:
        """Wait for X11 DISPLAY to become available."""
        log.debug("Waiting for DISPLAY :0")

        deadline = time.time() + self.STARTUP_TIMEOUT
        while time.time() < deadline:
            try:
                result = subprocess.run(
                    ["xdpyinfo", "-display", ":0"],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    log.debug("DISPLAY :0 is ready")
                    return True
            except Exception:
                pass

            time.sleep(0.5)

        return False

    def _launch_chromium(self) -> bool:
        """Launch Chromium in kiosk mode."""
        # Chromium is launched by .xsession, just verify it's running
        log.debug("Waiting for Chromium")

        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                result = subprocess.run(
                    ["pgrep", "-f", "chromium"],
                    capture_output=True,
                )
                if result.returncode == 0:
                    self._chromium_pid = int(result.stdout.decode().strip().split()[0])
                    log.debug("Chromium running, PID: %d", self._chromium_pid)
                    return True
            except Exception:
                pass

            time.sleep(0.5)

        return False

    def stop(self):
        """Stop KUI mode."""
        log.info("Stopping KUI mode")

        # Kill Chromium
        if self._chromium_pid:
            try:
                os.kill(self._chromium_pid, signal.SIGTERM)
                time.sleep(1)
                os.kill(self._chromium_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._chromium_pid = None

        # Kill X11
        if self._x_pid:
            try:
                os.kill(self._x_pid, signal.SIGTERM)
                time.sleep(1)
                os.kill(self._x_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self._x_pid = None

        # Also try pkill as fallback
        subprocess.run(["pkill", "-f", "chromium"], capture_output=True)
        subprocess.run(["pkill", "-f", "Xorg"], capture_output=True)

    def is_running(self) -> bool:
        """Check if KUI is running."""
        try:
            # Check for X11
            result = subprocess.run(
                ["pgrep", "-f", "Xorg"],
                capture_output=True,
            )
            x_running = result.returncode == 0

            # Check for Chromium
            result = subprocess.run(
                ["pgrep", "-f", "chromium"],
                capture_output=True,
            )
            chromium_running = result.returncode == 0

            return x_running and chromium_running

        except Exception:
            return False

    def get_error(self) -> str:
        """Get the last error message."""
        return self._error

    def get_status(self) -> dict:
        """Get current KUI status."""
        return {
            "running": self.is_running(),
            "x_pid": self._x_pid,
            "chromium_pid": self._chromium_pid,
            "vt": self._vt,
            "error": self._error,
            "config": {
                "driver": self._config.driver if self._config else None,
                "resolution": self._config.resolution if self._config else None,
                "disable_3d": self._config.disable_3d if self._config else None,
            } if self._config else None,
        }
