"""
SecuBox Console TUI — Menu Screen
Settings and system menu.
"""
from __future__ import annotations
import subprocess
import os
from pathlib import Path

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Label, Button, DataTable
from textual.containers import Container, Horizontal, Vertical
from textual import work

from ..theme import get_board_name, get_board_badge, get_board_theme
from secubox_core.kiosk import (
    detect_board_type, get_board_model, get_board_capabilities,
    kiosk_status
)


class SystemInfo(Static):
    """System information panel."""

    def compose(self) -> ComposeResult:
        yield Label("System Information", classes="card-title")
        yield DataTable(id="sysinfo-table")

    def on_mount(self) -> None:
        table = self.query_one("#sysinfo-table", DataTable)
        table.add_columns("Property", "Value")
        table.show_header = False
        self.refresh_info()

    @work
    async def refresh_info(self) -> None:
        """Refresh system information."""
        table = self.query_one("#sysinfo-table", DataTable)
        table.clear()

        # Board info
        board_type = detect_board_type()
        board_model = get_board_model()
        board_name = get_board_name()
        capabilities = get_board_capabilities()

        table.add_row("Board Type", board_type)
        table.add_row("Model", board_model)
        table.add_row("Edition", board_name)
        table.add_row("Profile", capabilities.get("profile", "unknown"))

        # Hardware
        table.add_row("CPU Cores", str(capabilities.get("cpu_cores", "-")))
        table.add_row("Max RAM", f"{capabilities.get('max_ram_gb', '-')} GB")
        table.add_row("LAN Ports", str(capabilities.get("lan_ports", "-")))
        table.add_row("SFP Ports", str(capabilities.get("sfp_ports", "-")))

        # System info
        hostname = self._get_hostname()
        kernel = self._get_kernel()
        debian_ver = self._get_debian_version()

        table.add_row("Hostname", hostname)
        table.add_row("Kernel", kernel)
        table.add_row("Debian", debian_ver)

        # Kiosk status
        kiosk = kiosk_status()
        kiosk_mode = kiosk.get("mode", "disabled")
        table.add_row("Kiosk Mode", kiosk_mode)

    def _get_hostname(self) -> str:
        try:
            return Path("/etc/hostname").read_text().strip()
        except Exception:
            return "unknown"

    def _get_kernel(self) -> str:
        try:
            return os.uname().release
        except Exception:
            return "unknown"

    def _get_debian_version(self) -> str:
        try:
            for line in Path("/etc/os-release").read_text().split("\n"):
                if line.startswith("VERSION_CODENAME="):
                    return line.split("=")[1].strip('"')
        except Exception:
            pass
        return "unknown"


class QuickActions(Static):
    """Quick action buttons."""

    def compose(self) -> ComposeResult:
        yield Label("Quick Actions", classes="card-title")
        with Vertical(id="action-list"):
            yield Button("Reboot System", id="btn-reboot", variant="warning")
            yield Button("Shutdown System", id="btn-shutdown", variant="error")
            yield Button("Restart All Services", id="btn-restart-all", variant="primary")
            yield Button("Enable GUI Kiosk", id="btn-kiosk", variant="default")
            yield Button("Exit Console", id="btn-exit", variant="default")


class MenuScreen(Screen):
    """Settings and menu screen."""

    BINDINGS = [
        ("d", "switch_screen('dashboard')", "Dashboard"),
        ("s", "switch_screen('services')", "Services"),
        ("n", "switch_screen('network')", "Network"),
        ("l", "switch_screen('logs')", "Logs"),
        ("m", "switch_screen('menu')", "Menu"),
        ("q", "quit", "Quit"),
        ("escape", "back", "Back"),
        # Vim navigation
        ("j", "next_button", "Down"),
        ("k", "prev_button", "Up"),
        ("h", "back", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._button_index = 0

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="menu-container"):
            with Horizontal():
                yield SystemInfo(id="sysinfo-panel")
                yield QuickActions(id="actions-panel")

            yield Label("", id="status-message")

        yield Footer()

    def _show_status(self, message: str) -> None:
        """Show status message."""
        try:
            label = self.query_one("#status-message", Label)
            label.update(message)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "btn-reboot":
            self._confirm_reboot()
        elif button_id == "btn-shutdown":
            self._confirm_shutdown()
        elif button_id == "btn-restart-all":
            self._restart_all_services()
        elif button_id == "btn-kiosk":
            self._toggle_kiosk()
        elif button_id == "btn-exit":
            self.app.exit()

    @work(exclusive=True)
    async def _confirm_reboot(self) -> None:
        """Reboot the system."""
        self._show_status("Rebooting system in 3 seconds...")
        try:
            subprocess.run(["shutdown", "-r", "+0"], timeout=5)
        except Exception as e:
            self._show_status(f"Error: {e}")

    @work(exclusive=True)
    async def _confirm_shutdown(self) -> None:
        """Shutdown the system."""
        self._show_status("Shutting down system...")
        try:
            subprocess.run(["shutdown", "-h", "now"], timeout=5)
        except Exception as e:
            self._show_status(f"Error: {e}")

    @work(exclusive=True)
    async def _restart_all_services(self) -> None:
        """Restart all SecuBox services."""
        self._show_status("Restarting all SecuBox services...")
        try:
            result = subprocess.run(
                ["systemctl", "restart", "secubox-*"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                self._show_status("All services restarted")
            else:
                self._show_status(f"Some services failed: {result.stderr[:50]}")
        except Exception as e:
            self._show_status(f"Error: {e}")

    @work(exclusive=True)
    async def _toggle_kiosk(self) -> None:
        """Toggle GUI kiosk mode."""
        status = kiosk_status()

        if status.get("enabled"):
            self._show_status("Disabling kiosk mode...")
            try:
                subprocess.run(
                    ["/usr/sbin/secubox-kiosk-setup", "disable"],
                    timeout=30
                )
                self._show_status("Kiosk mode disabled. Console mode active.")
            except Exception as e:
                self._show_status(f"Error: {e}")
        else:
            self._show_status("Enabling kiosk mode (X11)...")
            try:
                subprocess.run(
                    ["/usr/sbin/secubox-kiosk-setup", "enable", "--x11"],
                    timeout=120
                )
                self._show_status("Kiosk mode enabled. Reboot to activate.")
            except Exception as e:
                self._show_status(f"Error: {e}")

    def action_next_button(self) -> None:
        """Focus next button."""
        try:
            buttons = self.query("Button")
            if buttons:
                self._button_index = (self._button_index + 1) % len(buttons)
                buttons[self._button_index].focus()
        except Exception:
            pass

    def action_prev_button(self) -> None:
        """Focus previous button."""
        try:
            buttons = self.query("Button")
            if buttons:
                self._button_index = (self._button_index - 1) % len(buttons)
                buttons[self._button_index].focus()
        except Exception:
            pass

    def action_back(self) -> None:
        """Go back to dashboard."""
        self.app.switch_screen("dashboard")

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()
