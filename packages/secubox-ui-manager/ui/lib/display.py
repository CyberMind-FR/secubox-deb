"""
SecuBox UI Manager - Display Detection
=======================================

Detects display capabilities for mode selection.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List

from .debug import get_logger

log = get_logger("display")


@dataclass
class DisplayInfo:
    """Information about display capabilities."""
    has_graphics: bool  # X11/Wayland possible
    has_tty: bool  # TTY available
    has_framebuffer: bool  # Framebuffer available
    active_vts: List[int]  # Active virtual terminals
    x_display: Optional[str]  # DISPLAY if X running
    wayland_display: Optional[str]  # WAYLAND_DISPLAY if Wayland running


class DisplayDetector:
    """
    Detect display capabilities for mode selection.

    Usage:
        detector = DisplayDetector()
        info = detector.detect()
        if info.has_graphics:
            print("Can start KUI mode")
    """

    def detect(self) -> DisplayInfo:
        """Detect current display capabilities."""
        return DisplayInfo(
            has_graphics=self._check_graphics(),
            has_tty=self._check_tty(),
            has_framebuffer=self._check_framebuffer(),
            active_vts=self._get_active_vts(),
            x_display=self._get_x_display(),
            wayland_display=self._get_wayland_display(),
        )

    def _check_graphics(self) -> bool:
        """Check if graphics (X11/Wayland) is possible."""
        # Check for X11 server
        xinit_exists = Path("/usr/bin/xinit").exists() or Path("/usr/bin/startx").exists()

        # Check for Wayland compositor
        wayland_exists = (
            Path("/usr/bin/cage").exists()
            or Path("/usr/bin/sway").exists()
            or Path("/usr/bin/weston").exists()
        )

        # Check for display device
        has_display = (
            Path("/dev/dri").exists()
            or Path("/dev/fb0").exists()
            or any(Path("/sys/class/drm").glob("card*"))
        )

        result = (xinit_exists or wayland_exists) and has_display
        log.debug(
            "Graphics check: xinit=%s, wayland=%s, device=%s -> %s",
            xinit_exists,
            wayland_exists,
            has_display,
            result,
        )
        return result

    def _check_tty(self) -> bool:
        """Check if TTY is available."""
        # Check for at least one virtual terminal
        for i in range(1, 7):
            if Path(f"/dev/tty{i}").exists():
                return True
        return False

    def _check_framebuffer(self) -> bool:
        """Check if framebuffer is available."""
        return Path("/dev/fb0").exists()

    def _get_active_vts(self) -> List[int]:
        """Get list of active virtual terminals."""
        active = []
        for i in range(1, 13):
            vt_path = Path(f"/dev/tty{i}")
            if vt_path.exists():
                # Check if VT is active (has a process)
                try:
                    # fgconsole returns current VT
                    result = subprocess.run(
                        ["fgconsole"],
                        capture_output=True,
                        text=True,
                        timeout=2,
                    )
                    current_vt = int(result.stdout.strip())
                    if i == current_vt:
                        active.append(i)
                except Exception:
                    pass

                # Also check if getty is running
                try:
                    result = subprocess.run(
                        ["systemctl", "is-active", f"getty@tty{i}.service"],
                        capture_output=True,
                        text=True,
                        timeout=2,
                    )
                    if result.stdout.strip() == "active":
                        if i not in active:
                            active.append(i)
                except Exception:
                    pass

        return sorted(active)

    def _get_x_display(self) -> Optional[str]:
        """Get DISPLAY environment variable if X is running."""
        display = os.environ.get("DISPLAY")
        if display:
            # Verify X is actually running
            try:
                result = subprocess.run(
                    ["xdpyinfo"],
                    capture_output=True,
                    timeout=2,
                    env={"DISPLAY": display},
                )
                if result.returncode == 0:
                    return display
            except Exception:
                pass
        return None

    def _get_wayland_display(self) -> Optional[str]:
        """Get WAYLAND_DISPLAY if Wayland is running."""
        wayland = os.environ.get("WAYLAND_DISPLAY")
        if wayland:
            # Check socket exists
            xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
            socket_path = Path(xdg_runtime) / wayland
            if socket_path.exists():
                return wayland
        return None

    def find_free_vt(self) -> int:
        """Find a free virtual terminal for X11."""
        for i in range(7, 13):
            vt_path = Path(f"/dev/tty{i}")
            if vt_path.exists():
                # Check if VT is free (no X running on it)
                try:
                    result = subprocess.run(
                        ["fuser", f"/dev/tty{i}"],
                        capture_output=True,
                        timeout=2,
                    )
                    if result.returncode != 0:
                        # No process using this VT
                        log.debug("Found free VT: %d", i)
                        return i
                except Exception:
                    pass
        # Default to VT7
        return 7

    def can_start_kui(self) -> bool:
        """Check if KUI mode can be started."""
        info = self.detect()
        return info.has_graphics and not info.x_display

    def can_start_tui(self) -> bool:
        """Check if TUI mode can be started."""
        info = self.detect()
        return info.has_tty

    def get_recommended_mode(self) -> str:
        """Get recommended UI mode based on capabilities."""
        info = self.detect()

        if info.x_display:
            # X already running, use it
            return "kui"
        elif info.has_graphics:
            return "kui"
        elif info.has_tty:
            return "tui"
        else:
            return "console"
