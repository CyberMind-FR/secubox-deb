"""
SecuBox Console — SOC Fleet Overview Screen
Fleet-wide view of all registered edge nodes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from textual.app import ComposeResult
from textual.screen import Screen
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, DataTable, Footer, Header, Label
from textual.reactive import reactive

from ..soc_client import get_fleet_summary, get_fleet_nodes, is_soc_available
from ..widgets.header import BoardHeader


class FleetSummary(Static):
    """Fleet summary widget showing aggregate stats."""

    summary = reactive({})

    def compose(self) -> ComposeResult:
        yield Static("", id="fleet-summary-content")

    def watch_summary(self, value: dict) -> None:
        """Update display when summary changes."""
        content = self.query_one("#fleet-summary-content", Static)

        if not value:
            content.update("[dim]Loading fleet summary...[/]")
            return

        total = value.get("total_nodes", 0)
        online = value.get("nodes_online", 0)
        offline = value.get("nodes_offline", 0)
        critical = value.get("critical", 0)

        resources = value.get("resources", {})
        avg_cpu = resources.get("avg_cpu", 0)
        avg_mem = resources.get("avg_memory", 0)
        avg_disk = resources.get("avg_disk", 0)

        # Health color
        if critical > 0:
            health_color = "red"
        elif offline > total * 0.2:
            health_color = "yellow"
        else:
            health_color = "green"

        text = f"""
[bold]Fleet Overview[/]
Nodes: [{health_color}]{online}[/] online / {offline} offline / {total} total
Resources: CPU [cyan]{avg_cpu:.1f}%[/] | Mem [cyan]{avg_mem:.1f}%[/] | Disk [cyan]{avg_disk:.1f}%[/]
Alerts: {value.get('total_alerts', 0)} | Services Down: {value.get('services_down', 0)}
        """.strip()

        content.update(text)


class FleetNodesTable(DataTable):
    """Table showing all registered nodes."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "select_node", "Select", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def on_mount(self) -> None:
        """Set up table columns."""
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_column("Node", key="node_id", width=14)
        self.add_column("Hostname", key="hostname", width=20)
        self.add_column("Health", key="health", width=10)
        self.add_column("CPU", key="cpu", width=8)
        self.add_column("Mem", key="mem", width=8)
        self.add_column("Region", key="region", width=10)
        self.add_column("Last Seen", key="last_seen", width=12)

    def load_nodes(self, nodes: list) -> None:
        """Load nodes into the table."""
        self.clear()

        for node in nodes:
            health = node.get("health", "unknown")
            if health == "healthy":
                health_display = "[green]healthy[/]"
            elif health == "degraded":
                health_display = "[yellow]degraded[/]"
            elif health == "critical":
                health_display = "[red]CRITICAL[/]"
            else:
                health_display = "[dim]unknown[/]"

            # Format last seen
            last_seen = node.get("last_seen", "")
            if last_seen:
                try:
                    dt = datetime.fromisoformat(last_seen.rstrip("Z"))
                    delta = datetime.utcnow() - dt
                    if delta.total_seconds() < 60:
                        last_seen_display = "just now"
                    elif delta.total_seconds() < 3600:
                        last_seen_display = f"{int(delta.total_seconds() / 60)}m ago"
                    else:
                        last_seen_display = f"{int(delta.total_seconds() / 3600)}h ago"
                except:
                    last_seen_display = last_seen[:10]
            else:
                last_seen_display = "[dim]never[/]"

            self.add_row(
                node.get("node_id", "")[:12],
                node.get("hostname", "")[:18],
                health_display,
                f"{node.get('cpu', 0):.0f}%",
                f"{node.get('memory', 0):.0f}%",
                node.get("region", "default")[:8],
                last_seen_display,
                key=node.get("node_id")
            )

    def action_select_node(self) -> None:
        """Handle node selection."""
        if self.row_count > 0 and self.cursor_row is not None:
            row_key = self.get_row_at(self.cursor_row)
            if row_key:
                self.app.push_screen("soc_node", node_id=row_key.value)


class SOCFleetScreen(Screen):
    """SOC Fleet Overview Screen."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh", show=True),
        Binding("f", "filter_status", "Filter", show=True),
        Binding("1", "filter_critical", "Critical", show=False),
        Binding("2", "filter_degraded", "Degraded", show=False),
        Binding("3", "filter_all", "All", show=False),
        Binding("h", "pop_screen", "Back", show=True),
    ]

    status_filter: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield BoardHeader()
        yield Container(
            Vertical(
                FleetSummary(id="fleet-summary"),
                Static("", id="filter-status"),
                FleetNodesTable(id="nodes-table"),
                id="fleet-content"
            ),
            id="main"
        )
        yield Footer()

    async def on_mount(self) -> None:
        """Load fleet data on mount."""
        self.set_interval(30.0, self.refresh_data)
        await self.refresh_data()

    async def refresh_data(self) -> None:
        """Refresh fleet data."""
        # Check if SOC is available
        if not await is_soc_available():
            self.query_one("#fleet-summary", FleetSummary).summary = {
                "error": "SOC Gateway not available"
            }
            return

        # Load summary
        summary = await get_fleet_summary()
        if summary:
            self.query_one("#fleet-summary", FleetSummary).summary = summary

        # Load nodes
        nodes = await get_fleet_nodes(status=self.status_filter)
        self.query_one("#nodes-table", FleetNodesTable).load_nodes(nodes)

        # Update filter status
        filter_text = ""
        if self.status_filter:
            filter_text = f"[dim]Filter: {self.status_filter}[/]"
        self.query_one("#filter-status", Static).update(filter_text)

    def action_refresh(self) -> None:
        """Manual refresh."""
        self.run_worker(self.refresh_data())

    def action_filter_critical(self) -> None:
        """Filter to critical nodes only."""
        self.status_filter = "critical"
        self.run_worker(self.refresh_data())

    def action_filter_degraded(self) -> None:
        """Filter to degraded nodes only."""
        self.status_filter = "degraded"
        self.run_worker(self.refresh_data())

    def action_filter_all(self) -> None:
        """Clear filter."""
        self.status_filter = None
        self.run_worker(self.refresh_data())

    def action_filter_status(self) -> None:
        """Cycle through status filters."""
        filters = [None, "online", "offline", "critical"]
        try:
            idx = filters.index(self.status_filter)
            self.status_filter = filters[(idx + 1) % len(filters)]
        except ValueError:
            self.status_filter = None
        self.run_worker(self.refresh_data())
