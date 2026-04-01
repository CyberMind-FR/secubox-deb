"""
SecuBox Console TUI — Services Screen
Service management with start/stop/restart/enable/disable actions.
"""
from __future__ import annotations
import subprocess
from typing import Optional

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, DataTable, Static, Label, Button
from textual.containers import Container, Horizontal, Vertical
from textual.binding import Binding
from textual import work

from ..api_client import get_client


class ServiceActions(Static):
    """Action buttons for selected service."""

    def compose(self) -> ComposeResult:
        yield Label("Selected: (none)", id="selected-service")
        with Horizontal(id="action-buttons"):
            yield Button("Start", id="btn-start", variant="success")
            yield Button("Stop", id="btn-stop", variant="error")
            yield Button("Restart", id="btn-restart", variant="warning")
            yield Button("Enable", id="btn-enable", variant="primary")
            yield Button("Disable", id="btn-disable", variant="default")

    def update_selected(self, name: str) -> None:
        try:
            label = self.query_one("#selected-service", Label)
            label.update(f"Selected: {name}")
        except Exception:
            pass


class ServicesScreen(Screen):
    """Service management screen."""

    BINDINGS = [
        ("d", "switch_screen('dashboard')", "Dashboard"),
        ("s", "switch_screen('services')", "Services"),
        ("n", "switch_screen('network')", "Network"),
        ("l", "switch_screen('logs')", "Logs"),
        ("m", "switch_screen('menu')", "Menu"),
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        # Vim-style navigation
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
        ("enter", "toggle_service", "Toggle"),
        ("shift+r", "restart_service", "Restart"),
        ("e", "enable_service", "Enable"),
        ("shift+d", "disable_service", "Disable"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._selected_service: Optional[str] = None
        self._services: list = []

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="services-container"):
            yield Label("SecuBox Services", classes="card-title")
            yield DataTable(id="services-table")
            yield ServiceActions(id="service-actions")
            yield Label("", id="status-message")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize table and load services."""
        table = self.query_one("#services-table", DataTable)
        table.add_columns("Service", "Status", "Enabled", "PID")
        table.cursor_type = "row"
        table.zebra_stripes = True

        self.refresh_services()

    @work(exclusive=True)
    async def refresh_services(self) -> None:
        """Load services list."""
        # Try API first
        client = get_client()
        services = await client.services()

        if not services:
            # Fall back to systemctl
            services = await self._get_local_services()

        self._services = services
        self._update_table(services)

    async def _get_local_services(self) -> list:
        """Get services from systemctl."""
        services = []
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[0].replace(".service", "")
                        # Only show secubox services and key system services
                        if name.startswith("secubox-") or name in (
                            "nginx", "haproxy", "crowdsec", "nftables", "sshd", "dnsmasq"
                        ):
                            load = parts[1]
                            active = parts[2]
                            sub = parts[3]

                            # Get enabled status
                            enabled = self._is_service_enabled(f"{name}.service")

                            # Get PID
                            pid = self._get_service_pid(f"{name}.service")

                            services.append({
                                "name": name,
                                "status": active,
                                "sub": sub,
                                "enabled": enabled,
                                "pid": pid
                            })
        except Exception:
            pass
        return services

    def _is_service_enabled(self, unit: str) -> bool:
        """Check if service is enabled."""
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", unit],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() == "enabled"
        except Exception:
            return False

    def _get_service_pid(self, unit: str) -> str:
        """Get service PID."""
        try:
            result = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "--value", unit],
                capture_output=True, text=True, timeout=5
            )
            pid = result.stdout.strip()
            return pid if pid != "0" else "-"
        except Exception:
            return "-"

    def _update_table(self, services: list) -> None:
        """Update the services table."""
        try:
            table = self.query_one("#services-table", DataTable)
            table.clear()

            for svc in sorted(services, key=lambda x: x.get("name", "")):
                name = svc.get("name", "unknown")
                status = svc.get("status", svc.get("active", "unknown"))
                enabled = "yes" if svc.get("enabled") else "no"
                pid = str(svc.get("pid", "-"))

                table.add_row(name, status, enabled, pid)
        except Exception:
            pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        try:
            table = self.query_one("#services-table", DataTable)
            row_key = event.row_key
            row_data = table.get_row(row_key)
            if row_data:
                self._selected_service = row_data[0]
                actions = self.query_one("#service-actions", ServiceActions)
                actions.update_selected(self._selected_service)
        except Exception:
            pass

    def _show_status(self, message: str) -> None:
        """Show status message."""
        try:
            label = self.query_one("#status-message", Label)
            label.update(message)
        except Exception:
            pass

    @work(exclusive=True)
    async def _do_service_action(self, action: str) -> None:
        """Execute service action."""
        if not self._selected_service:
            self._show_status("No service selected")
            return

        service = self._selected_service
        self._show_status(f"{action.capitalize()}ing {service}...")

        try:
            result = subprocess.run(
                ["systemctl", action, f"{service}.service"],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                self._show_status(f"{service} {action}ed successfully")
            else:
                self._show_status(f"Failed to {action} {service}: {result.stderr.strip()}")

            # Refresh the list
            await self.refresh_services()

        except subprocess.TimeoutExpired:
            self._show_status(f"Timeout {action}ing {service}")
        except Exception as e:
            self._show_status(f"Error: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "btn-start":
            self._do_service_action("start")
        elif button_id == "btn-stop":
            self._do_service_action("stop")
        elif button_id == "btn-restart":
            self._do_service_action("restart")
        elif button_id == "btn-enable":
            self._do_service_action("enable")
        elif button_id == "btn-disable":
            self._do_service_action("disable")

    def action_cursor_down(self) -> None:
        """Move cursor down (j key)."""
        try:
            table = self.query_one("#services-table", DataTable)
            table.action_cursor_down()
        except Exception:
            pass

    def action_cursor_up(self) -> None:
        """Move cursor up (k key)."""
        try:
            table = self.query_one("#services-table", DataTable)
            table.action_cursor_up()
        except Exception:
            pass

    def action_toggle_service(self) -> None:
        """Toggle service (start if stopped, stop if running)."""
        if not self._selected_service:
            return

        # Find current status
        for svc in self._services:
            if svc.get("name") == self._selected_service:
                status = svc.get("status", "inactive")
                if status == "active":
                    self._do_service_action("stop")
                else:
                    self._do_service_action("start")
                return

    def action_restart_service(self) -> None:
        """Restart selected service."""
        self._do_service_action("restart")

    def action_enable_service(self) -> None:
        """Enable selected service."""
        self._do_service_action("enable")

    def action_disable_service(self) -> None:
        """Disable selected service."""
        self._do_service_action("disable")

    def action_refresh(self) -> None:
        """Manual refresh."""
        self.refresh_services()

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()
