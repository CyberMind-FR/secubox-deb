"""
SecuBox Console TUI — Dashboard Screen
Main dashboard with system metrics and health status.
"""
from __future__ import annotations
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, ProgressBar, DataTable, Label
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.reactive import reactive
from textual import work

from ..api_client import get_client
from ..theme import get_board_name, get_board_badge, get_board_theme


class MetricCard(Static):
    """A card displaying a single metric with progress bar."""

    def __init__(
        self,
        title: str,
        value: str = "0%",
        progress: float = 0.0,
        *,
        id: str | None = None
    ) -> None:
        super().__init__(id=id)
        self.title = title
        self._value = value
        self._progress = progress

    def compose(self) -> ComposeResult:
        yield Label(self.title, classes="metric-label")
        yield Label(self._value, id=f"{self.id}-value", classes="metric-value")
        yield ProgressBar(total=100, show_percentage=False, id=f"{self.id}-bar")

    def update_value(self, value: str, progress: float) -> None:
        self._value = value
        self._progress = progress
        try:
            value_label = self.query_one(f"#{self.id}-value", Label)
            value_label.update(value)
            bar = self.query_one(f"#{self.id}-bar", ProgressBar)
            bar.update(progress=progress)
        except Exception:
            pass


class HealthCard(Static):
    """Card showing overall health status."""

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id)
        self._health = "unknown"
        self._score = 0

    def compose(self) -> ComposeResult:
        yield Label("System Health", classes="card-title")
        yield Label("UNKNOWN", id="health-status", classes="status-unknown")
        yield Label("Score: --", id="health-score", classes="metric-value")

    def update_health(self, health: str, score: int = 0) -> None:
        self._health = health.lower()
        self._score = score
        try:
            status_label = self.query_one("#health-status", Label)
            score_label = self.query_one("#health-score", Label)

            status_label.update(health.upper())

            # Update CSS class based on health
            status_label.remove_class("status-healthy", "status-degraded", "status-critical", "status-unknown")
            status_label.add_class(f"status-{self._health}")

            score_label.update(f"Score: {score}%")
        except Exception:
            pass


class UptimeCard(Static):
    """Card showing system uptime."""

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id)
        self._uptime = "unknown"

    def compose(self) -> ComposeResult:
        yield Label("Uptime", classes="card-title")
        yield Label("--", id="uptime-value", classes="metric-value")

    def update_uptime(self, uptime: str) -> None:
        self._uptime = uptime
        try:
            value_label = self.query_one("#uptime-value", Label)
            value_label.update(uptime)
        except Exception:
            pass


class BoardInfoCard(Static):
    """Card showing board information."""

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id)

    def compose(self) -> ComposeResult:
        name = get_board_name()
        badge = get_board_badge()

        yield Horizontal(
            Label(name, classes="card-title"),
            Label(badge, classes="board-badge") if badge else Static(""),
        )
        yield Label("Loading...", id="board-model", classes="metric-label")

    def update_model(self, model: str) -> None:
        try:
            model_label = self.query_one("#board-model", Label)
            model_label.update(model)
        except Exception:
            pass


class ServicesSummary(Static):
    """Summary of running services."""

    def compose(self) -> ComposeResult:
        yield Label("Services", classes="card-title")
        yield DataTable(id="services-table")

    def on_mount(self) -> None:
        table = self.query_one("#services-table", DataTable)
        table.add_columns("Service", "Status")
        table.cursor_type = "row"


class DashboardScreen(Screen):
    """Main dashboard screen with system metrics."""

    BINDINGS = [
        ("d", "switch_screen('dashboard')", "Dashboard"),
        ("s", "switch_screen('services')", "Services"),
        ("n", "switch_screen('network')", "Network"),
        ("l", "switch_screen('logs')", "Logs"),
        ("m", "switch_screen('menu')", "Menu"),
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    # Reactive properties for auto-refresh
    cpu_percent: reactive[float] = reactive(0.0)
    mem_percent: reactive[float] = reactive(0.0)
    disk_percent: reactive[float] = reactive(0.0)
    health_status: reactive[str] = reactive("unknown")

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="dashboard-container"):
            # Top row: Board info and health
            with Horizontal(id="top-row"):
                yield BoardInfoCard(id="board-card")
                yield HealthCard(id="health-card")
                yield UptimeCard(id="uptime-card")

            # Middle row: Resource metrics
            with Horizontal(id="metrics-row"):
                yield MetricCard("CPU", "0%", 0.0, id="cpu-metric")
                yield MetricCard("Memory", "0%", 0.0, id="mem-metric")
                yield MetricCard("Disk", "0%", 0.0, id="disk-metric")

            # Bottom: Services summary
            yield ServicesSummary(id="services-summary")

        yield Footer()

    def on_mount(self) -> None:
        """Start periodic refresh on mount."""
        self.refresh_data()
        self.set_interval(2.0, self.refresh_data)

    @work(exclusive=True)
    async def refresh_data(self) -> None:
        """Fetch data from APIs and update display."""
        client = get_client()

        try:
            # Get dashboard data
            dashboard = await client.dashboard()
            resources = await client.resources()
            health_data = await client.health()
            services = await client.services()
            board = await client.board_info()

            # Update metrics
            cpu = resources.get("cpu_percent", 0)
            mem = resources.get("memory_percent", 0)
            disk = resources.get("disk_percent", 0)

            self._update_metrics(cpu, mem, disk)

            # Update health
            health = health_data.get("health", "unknown")
            self._update_health(health)

            # Update uptime
            uptime = dashboard.get("uptime", await self._get_local_uptime())
            self._update_uptime(uptime)

            # Update board model
            model = board.get("model", await self._get_local_model())
            self._update_board_model(model)

            # Update services table
            self._update_services(services[:8])  # Top 8 services

        except Exception:
            # Fall back to local data
            await self._refresh_local()

    async def _refresh_local(self) -> None:
        """Refresh using local system data when APIs unavailable."""
        cpu = await self._get_local_cpu()
        mem = await self._get_local_memory()
        disk = await self._get_local_disk()
        uptime = await self._get_local_uptime()
        model = await self._get_local_model()
        services = await self._get_local_services()

        self._update_metrics(cpu, mem, disk)
        self._update_uptime(uptime)
        self._update_board_model(model)
        self._update_services(services[:8])
        self._update_health("unknown")

    def _update_metrics(self, cpu: float, mem: float, disk: float) -> None:
        """Update metric cards."""
        try:
            cpu_card = self.query_one("#cpu-metric", MetricCard)
            cpu_card.update_value(f"{cpu:.1f}%", cpu)

            mem_card = self.query_one("#mem-metric", MetricCard)
            mem_card.update_value(f"{mem:.1f}%", mem)

            disk_card = self.query_one("#disk-metric", MetricCard)
            disk_card.update_value(f"{disk:.1f}%", disk)
        except Exception:
            pass

    def _update_health(self, health: str) -> None:
        """Update health card."""
        try:
            health_card = self.query_one("#health-card", HealthCard)
            # Calculate simple score
            score = {"healthy": 100, "degraded": 60, "critical": 20}.get(health.lower(), 0)
            health_card.update_health(health, score)
        except Exception:
            pass

    def _update_uptime(self, uptime: str) -> None:
        """Update uptime card."""
        try:
            uptime_card = self.query_one("#uptime-card", UptimeCard)
            uptime_card.update_uptime(uptime)
        except Exception:
            pass

    def _update_board_model(self, model: str) -> None:
        """Update board model display."""
        try:
            board_card = self.query_one("#board-card", BoardInfoCard)
            board_card.update_model(model)
        except Exception:
            pass

    def _update_services(self, services: list) -> None:
        """Update services table."""
        try:
            table = self.query_one("#services-table", DataTable)
            table.clear()
            for svc in services:
                name = svc.get("name", svc.get("unit", "unknown"))
                status = svc.get("status", svc.get("active", "unknown"))
                table.add_row(name, status)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # Local fallback methods
    # ═══════════════════════════════════════════════════════════════════

    async def _get_local_cpu(self) -> float:
        """Get CPU usage from /proc/stat."""
        try:
            load_path = Path("/proc/loadavg")
            if load_path.exists():
                load = float(load_path.read_text().split()[0])
                # Normalize by CPU count
                cpu_count = len([l for l in Path("/proc/cpuinfo").read_text().split("\n") if "processor" in l])
                return min(100.0, (load / max(1, cpu_count)) * 100)
        except Exception:
            pass
        return 0.0

    async def _get_local_memory(self) -> float:
        """Get memory usage from /proc/meminfo."""
        try:
            meminfo = Path("/proc/meminfo").read_text()
            total = available = 0
            for line in meminfo.split("\n"):
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1])
            if total > 0:
                return ((total - available) / total) * 100
        except Exception:
            pass
        return 0.0

    async def _get_local_disk(self) -> float:
        """Get disk usage for root filesystem."""
        try:
            result = subprocess.run(
                ["df", "-h", "/"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        percent = parts[4].rstrip("%")
                        return float(percent)
        except Exception:
            pass
        return 0.0

    async def _get_local_uptime(self) -> str:
        """Get uptime from /proc/uptime."""
        try:
            uptime_secs = float(Path("/proc/uptime").read_text().split()[0])
            days = int(uptime_secs // 86400)
            hours = int((uptime_secs % 86400) // 3600)
            mins = int((uptime_secs % 3600) // 60)
            if days > 0:
                return f"{days}d {hours}h {mins}m"
            elif hours > 0:
                return f"{hours}h {mins}m"
            return f"{mins}m"
        except Exception:
            return "unknown"

    async def _get_local_model(self) -> str:
        """Get board model from device-tree or DMI."""
        # Try device-tree first
        model_path = Path("/proc/device-tree/model")
        if model_path.exists():
            try:
                return model_path.read_text().strip().rstrip("\x00")
            except Exception:
                pass

        # Try DMI
        dmi_product = Path("/sys/class/dmi/id/product_name")
        if dmi_product.exists():
            try:
                return dmi_product.read_text().strip()
            except Exception:
                pass

        return "Unknown"

    async def _get_local_services(self) -> list:
        """Get running services from systemctl."""
        services = []
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n")[:15]:
                    parts = line.split()
                    if parts:
                        name = parts[0].replace(".service", "")
                        if name.startswith("secubox-"):
                            services.append({"name": name, "status": "running"})
        except Exception:
            pass
        return services

    def action_refresh(self) -> None:
        """Manual refresh action."""
        self.refresh_data()

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()
