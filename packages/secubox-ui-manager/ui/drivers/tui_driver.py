"""
SecuBox UI Manager - TUI Driver (Terminal UI)
==============================================

Manages the Textual-based Terminal UI.

Responsibilities:
    - Check TTY availability
    - Start Textual app on TTY
    - Fallback to bash TUI if Textual unavailable
"""

import os
import subprocess
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from ..lib.debug import get_logger
from ..lib.display import DisplayDetector

log = get_logger("tui")


class TUIDriver:
    """
    TUI (Terminal UI) driver.

    Usage:
        driver = TUIDriver()
        if driver.can_start():
            success = driver.start()
    """

    # Configuration
    TUI_TTY = "/dev/tty1"
    TEXTUAL_APP = "secubox_console.app:SecuBoxConsole"
    BASH_TUI_PATH = "/usr/sbin/secubox-console-tui"

    def __init__(self):
        self._display = DisplayDetector()
        self._process: Optional[subprocess.Popen] = None
        self._error: str = ""
        self._using_textual: bool = False

    def can_start(self) -> bool:
        """Check if TUI mode can be started."""
        if not self._display.can_start_tui():
            self._error = "No TTY available"
            return False

        # Check for either Textual or bash TUI
        has_textual = self._check_textual()
        has_bash_tui = Path(self.BASH_TUI_PATH).exists()

        if not has_textual and not has_bash_tui:
            self._error = "Neither Textual nor bash TUI available"
            return False

        return True

    def _check_textual(self) -> bool:
        """Check if Textual and the app are available."""
        try:
            import importlib
            importlib.import_module("textual")
            return True
        except ImportError:
            return False

    def start(self) -> bool:
        """
        Start TUI mode.

        Returns:
            True if started successfully
        """
        log.info("Starting TUI mode")

        try:
            # Try Textual first
            if self._check_textual():
                return self._start_textual()

            # Fallback to bash TUI
            if Path(self.BASH_TUI_PATH).exists():
                return self._start_bash_tui()

            self._error = "No TUI implementation available"
            return False

        except Exception as e:
            self._error = str(e)
            log.error("TUI start failed: %s", e)
            return False

    def _start_textual(self) -> bool:
        """Start the Textual-based TUI."""
        log.info("Starting Textual TUI")
        self._using_textual = True

        try:
            # Run as Python module
            cmd = [
                sys.executable, "-m",
                "textual", "run",
                self.TEXTUAL_APP,
            ]

            env = os.environ.copy()
            env["TERM"] = "xterm-256color"

            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                env=env,
            )

            # Wait a moment and check if still running
            time.sleep(1)
            if self._process.poll() is not None:
                self._error = "Textual TUI exited immediately"
                return False

            log.info("Textual TUI started, PID: %d", self._process.pid)
            return True

        except Exception as e:
            self._error = f"Failed to start Textual TUI: {e}"
            log.error(self._error)
            return False

    def _start_bash_tui(self) -> bool:
        """Start the bash-based TUI fallback."""
        log.info("Starting bash TUI (fallback)")
        self._using_textual = False

        try:
            self._process = subprocess.Popen(
                [self.BASH_TUI_PATH],
                stdin=subprocess.DEVNULL,
            )

            # Wait a moment and check if still running
            time.sleep(1)
            if self._process.poll() is not None:
                self._error = "Bash TUI exited immediately"
                return False

            log.info("Bash TUI started, PID: %d", self._process.pid)
            return True

        except Exception as e:
            self._error = f"Failed to start bash TUI: {e}"
            log.error(self._error)
            return False

    def stop(self):
        """Stop TUI mode."""
        log.info("Stopping TUI mode")

        if self._process:
            try:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
            except Exception as e:
                log.debug("Error stopping TUI: %s", e)
            finally:
                self._process = None

    def is_running(self) -> bool:
        """Check if TUI is running."""
        if self._process:
            return self._process.poll() is None
        return False

    def get_error(self) -> str:
        """Get the last error message."""
        return self._error

    def get_status(self) -> dict:
        """Get current TUI status."""
        return {
            "running": self.is_running(),
            "pid": self._process.pid if self._process else None,
            "using_textual": self._using_textual,
            "error": self._error,
        }


class TUIApp:
    """
    Simple embedded TUI application.

    This is a minimal fallback if the full Textual app isn't available.
    Uses basic ANSI escape codes for display.
    """

    def __init__(self):
        self._running = False

    def run(self):
        """Run the minimal TUI."""
        import sys
        import tty
        import termios

        self._running = True
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            tty.setraw(sys.stdin.fileno())

            # Clear screen
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write("\033[?25l")  # Hide cursor
            sys.stdout.flush()

            self._draw_header()
            self._draw_menu()

            while self._running:
                ch = sys.stdin.read(1)
                if ch == 'q':
                    break
                elif ch == '\x03':  # Ctrl-C
                    break

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            sys.stdout.write("\033[?25h")  # Show cursor
            sys.stdout.write("\033[2J\033[H")  # Clear screen
            sys.stdout.flush()

    def _draw_header(self):
        """Draw the header."""
        import sys
        sys.stdout.write("\033[1;1H")
        sys.stdout.write("\033[44;97m")  # Blue background, white text
        sys.stdout.write(" SecuBox Console ".center(80))
        sys.stdout.write("\033[0m\n")
        sys.stdout.flush()

    def _draw_menu(self):
        """Draw the menu."""
        import sys
        sys.stdout.write("\033[3;1H")
        sys.stdout.write("  [1] System Status\n")
        sys.stdout.write("  [2] Network Config\n")
        sys.stdout.write("  [3] Security Dashboard\n")
        sys.stdout.write("  [4] Logs\n")
        sys.stdout.write("  [q] Quit\n")
        sys.stdout.flush()
