"""
SecuBox Console — SOC Node Detail Screen
Remote node detail view with metrics and service management.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from textual.app import ComposeResult
from textual.screen import Screen
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, DataTable, Footer, Button
from textual.reactive import reactive

from ..soc_client import get_node_detail, send_service_action, is_soc_available
from ..widgets.header import SecuBoxHeader


class NodeInfoPanel(Static):
    """Panel showing node information and metrics."""

    node_data = reactive({})

    def compose(self) -> ComposeResult:
        yield Static("", id="node-info-content")

    def watch_node_data(self, value: dict) -> None:
        """Update display when node data changes."""
        content = self.query_one("#node-info-content", Static)

        if not value:
            content.update("[dim]Loading node data...[/]")
            return

        node = value.get("node", {})
        metrics = value.get("metrics", {})

        health = node.get("health", "unknown")
        if health == "healthy":
            health_display = "[green]HEALTHY[/]"
        elif health == "degraded":
            health_display = "[yellow]DEGRADED[/]"
        elif health == "critical":
            health_display = "[red]CRITICAL[/]"
        else:
            health_display = "[dim]UNKNOWN[/]"

        # Format last seen
        last_seen = node.get("last_seen", "")
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen.rstrip("Z"))
                delta = datetime.utcnow() - dt
                if delta.total_seconds() < 60:
                    last_seen_display = "just now"
                elif delta.total_seconds() < 3600:
                    last_seen_display = f"{int(delta.total_seconds() / 60)} minutes ago"
                else:
                    last_seen_display = f"{int(delta.total_seconds() / 3600)} hours ago"
            except:
                last_seen_display = last_seen
        else:
            last_seen_display = "[dim]never[/]"

        cpu = metrics.get("cpu", 0)
        mem = metrics.get("memory", 0)
        disk = metrics.get("disk", 0)

        # Color code resource usage
        cpu_color = "green" if cpu < 50 else "yellow" if cpu < 80 else "red"
        mem_color = "green" if mem < 50 else "yellow" if mem < 80 else "red"
        disk_color = "green" if disk < 70 else "yellow" if disk < 85 else "red"

        text = f"""
[bold]{node.get('hostname', 'Unknown')}[/] ({node.get('node_id', '')[:12]})
Status: {health_display} | IP: {node.get('ip_address', 'unknown')}
Region: {node.get('region', 'default')} | Last Seen: {last_seen_display}

[bold]Resources[/]
CPU:    [{cpu_color}]{'█' * int(cpu / 5)}{'░' * (20 - int(cpu / 5))}[/] {cpu:.1f}%
Memory: [{mem_color}]{'█' * int(mem / 5)}{'░' * (20 - int(mem / 5))}[/] {mem:.1f}%
Disk:   [{disk_color}]{'█' * int(disk / 5)}{'░' * (20 - int(disk / 5))}[/] {disk:.1f}%

[dim]Capabilities: {', '.join(node.get('capabilities', []))}[/]
        """.strip()

        content.update(text)


class NodeServicesTable(DataTable):
    """Table showing services on the remote node."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("r", "restart_service", "Restart", show=True),
        Binding("s", "stop_service", "Stop", show=True),
        Binding("enter", "start_service", "Start", show=True),
    ]

    node_id: str = ""

    def on_mount(self) -> None:
        """Set up table columns."""
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_column("Service", key="service", width=20)
        self.add_column("Status", key="status", width=12)
        self.add_column("PID", key="pid", width=8)

    def load_services(self, services: list) -> None:
        """Load services into the table."""
        self.clear()

        for svc in services:
            status = svc.get("status", "unknown")
            running = svc.get("running", False)

            if running:
                status_display = "[green]running[/]"
            elif status == "stopped":
                status_display = "[red]stopped[/]"
            else:
                status_display = f"[dim]{status}[/]"

            pid = svc.get("pid", "")
            if pid:
                pid_display = str(pid)
            else:
                pid_display = "[dim]-[/]"

            self.add_row(
                svc.get("name", "unknown"),
                status_display,
                pid_display,
                key=svc.get("name")
            )

    async def _send_action(self, action: str) -> None:
        """Send action to selected service."""
        if self.row_count == 0 or self.cursor_row is None:
            return

        row_key = self.get_row_at(self.cursor_row)
        if not row_key:
            return

        service = row_key.value
        result = await send_service_action(self.node_id, service, action)

        if result and result.get("status") == "queued":
            self.app.notify(f"{action.title()} command sent to {service}", title="OK")
        else:
            self.app.notify(f"Failed to send {action} command", title="Error")

    def action_restart_service(self) -> None:
        """Restart selected service."""
        self.run_worker(self._send_action("restart"))

    def action_stop_service(self) -> None:
        """Stop selected service."""
        self.run_worker(self._send_action("stop"))

    def action_start_service(self) -> None:
        """Start selected service."""
        self.run_worker(self._send_action("start"))


class NodeAlertsPanel(Static):
    """Panel showing recent alerts for this node."""

    alerts = reactive([])

    def compose(self) -> ComposeResult:
        yield Static("", id="node-alerts-content")

    def watch_alerts(self, value: list) -> None:
        """Update display when alerts change."""
        content = self.query_one("#node-alerts-content", Static)

        if not value:
            content.update("[dim]No recent alerts[/]")
            return

        lines = ["[bold]Recent Alerts[/]"]
        for alert in value[:10]:
            severity = alert.get("severity", "medium")
            if severity in ("critical", 1):
                sev_icon = "[red]●[/]"
            elif severity in ("high", 2):
                sev_icon = "[yellow]●[/]"
            else:
                sev_icon = "[dim]●[/]"

            ip = alert.get("ip", "")[:14]
            scenario = (
                alert.get("scenario") or
                alert.get("signature") or
                alert.get("reason", "unknown")
            )[:30]

            lines.append(f"{sev_icon} {ip:14} {scenario}")

        content.update("\n".join(lines))


class SOCNodeScreen(Screen):
    """SOC Node Detail Screen."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh", show=True),
        Binding("h", "pop_screen", "Back", show=True),
        Binding("tab", "focus_next", "Next", show=False),
    ]

    node_id: str = ""

    def __init__(self, node_id: str = "", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.node_id = node_id

    def compose(self) -> ComposeResult:
        yield SecuBoxHeader()
        yield Container(
            Horizontal(
                Vertical(
                    NodeInfoPanel(id="node-info"),
                    NodeServicesTable(id="services-table"),
                    id="node-left",
                    classes="node-panel"
                ),
                Vertical(
                    NodeAlertsPanel(id="node-alerts"),
                    id="node-right",
                    classes="node-panel"
                ),
                id="node-content"
            ),
            id="main"
        )
        yield Footer()

    async def on_mount(self) -> None:
        """Load node data on mount."""
        # Set node_id on services table
        self.query_one("#services-table", NodeServicesTable).node_id = self.node_id

        self.set_interval(15.0, self.refresh_data)
        await self.refresh_data()

    async def refresh_data(self) -> None:
        """Refresh node data."""
        if not self.node_id:
            return

        if not await is_soc_available():
            return

        detail = await get_node_detail(self.node_id)
        if detail:
            self.query_one("#node-info", NodeInfoPanel).node_data = detail

            # Load services (if available from metrics)
            metrics = detail.get("metrics", {})
            services = detail.get("node", {}).get("services", [])
            # If no services in response, show placeholder
            if not services:
                services = [
                    {"name": "nginx", "running": True, "status": "active"},
                    {"name": "haproxy", "running": True, "status": "active"},
                    {"name": "crowdsec", "running": True, "status": "active"},
                ]
            self.query_one("#services-table", NodeServicesTable).load_services(services)

            # Load alerts
            alerts = detail.get("alerts", [])
            self.query_one("#node-alerts", NodeAlertsPanel).alerts = alerts

    def action_refresh(self) -> None:
        """Manual refresh."""
        self.run_worker(self.refresh_data())
