"""
SecuBox Console — SOC Alerts Screen
Unified alert stream from all edge nodes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from textual.app import ComposeResult
from textual.screen import Screen
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.widgets import Static, DataTable, Footer
from textual.reactive import reactive

from ..soc_client import get_alerts, get_correlated_threats, get_correlation_summary, is_soc_available
from ..widgets.header import SecuBoxHeader


class CorrelationSummary(Static):
    """Summary of correlated threats."""

    summary = reactive({})

    def compose(self) -> ComposeResult:
        yield Static("", id="correlation-content")

    def watch_summary(self, value: dict) -> None:
        """Update display when summary changes."""
        content = self.query_one("#correlation-content", Static)

        if not value:
            content.update("[dim]Loading correlation data...[/]")
            return

        total = value.get("total_threats", 0)
        nodes_under_attack = value.get("nodes_under_attack", 0)

        by_severity = value.get("by_severity", {})
        critical = by_severity.get("critical", 0)
        high = by_severity.get("high", 0)

        if total == 0:
            content.update("[green]No correlated threats detected[/]")
            return

        severity_color = "red" if critical > 0 else "yellow" if high > 0 else "cyan"

        text = f"""
[bold]Threat Correlation[/]
Active Threats: [{severity_color}]{total}[/] | Nodes Under Attack: {nodes_under_attack}
Severity: [red]{critical}[/] critical | [yellow]{high}[/] high
        """.strip()

        content.update(text)


class AlertsTable(DataTable):
    """Table showing unified alerts."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("enter", "view_alert", "View", show=True),
        Binding("a", "acknowledge", "Ack", show=True),
    ]

    def on_mount(self) -> None:
        """Set up table columns."""
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_column("Time", key="time", width=12)
        self.add_column("Node", key="node", width=14)
        self.add_column("Source", key="source", width=10)
        self.add_column("Severity", key="severity", width=10)
        self.add_column("IP", key="ip", width=16)
        self.add_column("Reason", key="reason", width=30)

    def load_alerts(self, alerts: list) -> None:
        """Load alerts into the table."""
        self.clear()

        for alert in alerts:
            # Format timestamp
            ts = alert.get("timestamp") or alert.get("created_at", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.rstrip("Z"))
                    time_display = dt.strftime("%H:%M:%S")
                except:
                    time_display = ts[:8]
            else:
                time_display = "[dim]unknown[/]"

            # Severity coloring
            severity = alert.get("severity", "medium")
            if isinstance(severity, int):
                if severity <= 1:
                    severity = "critical"
                elif severity == 2:
                    severity = "high"
                elif severity == 3:
                    severity = "medium"
                else:
                    severity = "low"

            if severity == "critical":
                sev_display = "[red bold]CRITICAL[/]"
            elif severity == "high":
                sev_display = "[red]high[/]"
            elif severity == "medium":
                sev_display = "[yellow]medium[/]"
            else:
                sev_display = "[dim]low[/]"

            # Get reason/scenario
            reason = (
                alert.get("scenario") or
                alert.get("signature") or
                alert.get("reason") or
                alert.get("rule_id") or
                "unknown"
            )
            if len(reason) > 28:
                reason = reason[:28] + "..."

            self.add_row(
                time_display,
                alert.get("node_hostname", alert.get("node_id", ""))[:12],
                alert.get("source", "unknown")[:8],
                sev_display,
                alert.get("ip", "")[:14],
                reason,
                key=str(hash(f"{ts}{alert.get('ip')}"))
            )

    def action_view_alert(self) -> None:
        """View alert details."""
        if self.row_count > 0 and self.cursor_row is not None:
            self.app.notify("Alert details view not yet implemented", title="Info")

    def action_acknowledge(self) -> None:
        """Acknowledge selected alert."""
        if self.row_count > 0 and self.cursor_row is not None:
            self.app.notify("Alert acknowledged", title="OK")


class ThreatsTable(DataTable):
    """Table showing correlated threats."""

    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    def on_mount(self) -> None:
        """Set up table columns."""
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_column("IP", key="ip", width=16)
        self.add_column("Nodes", key="nodes", width=8)
        self.add_column("Hits", key="hits", width=8)
        self.add_column("Severity", key="severity", width=10)
        self.add_column("Action", key="action", width=14)
        self.add_column("Scenarios", key="scenarios", width=25)

    def load_threats(self, threats: list) -> None:
        """Load threats into the table."""
        self.clear()

        for threat in threats:
            severity = threat.get("severity", "medium")
            if severity == "critical":
                sev_display = "[red bold]CRITICAL[/]"
            elif severity == "high":
                sev_display = "[red]high[/]"
            else:
                sev_display = "[yellow]medium[/]"

            action = threat.get("recommended_action", "monitor")
            if action == "block_globally":
                action_display = "[red]BLOCK[/]"
            elif action == "rate_limit":
                action_display = "[yellow]rate limit[/]"
            else:
                action_display = "[dim]monitor[/]"

            scenarios = ", ".join(threat.get("scenarios", [])[:2])
            if len(scenarios) > 23:
                scenarios = scenarios[:23] + "..."

            self.add_row(
                threat.get("source_ip", ""),
                str(len(threat.get("nodes_affected", []))),
                str(threat.get("total_hits", 0)),
                sev_display,
                action_display,
                scenarios,
                key=threat.get("threat_id", threat.get("source_ip", ""))
            )


class SOCAlertsScreen(Screen):
    """SOC Alerts Screen with unified alert stream."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh", show=True),
        Binding("1", "filter_critical", "Critical", show=True),
        Binding("2", "filter_high", "High", show=False),
        Binding("3", "filter_all", "All", show=False),
        Binding("t", "toggle_view", "Threats", show=True),
        Binding("h", "pop_screen", "Back", show=True),
    ]

    severity_filter: Optional[str] = None
    show_threats: bool = False

    def compose(self) -> ComposeResult:
        yield SecuBoxHeader()
        yield Container(
            Vertical(
                CorrelationSummary(id="correlation-summary"),
                Static("[bold]Alerts[/] (press [cyan]t[/] for threats view)", id="view-label"),
                AlertsTable(id="alerts-table"),
                ThreatsTable(id="threats-table"),
                id="alerts-content"
            ),
            id="main"
        )
        yield Footer()

    async def on_mount(self) -> None:
        """Load alerts on mount."""
        # Hide threats table initially
        self.query_one("#threats-table").display = False

        self.set_interval(15.0, self.refresh_data)
        await self.refresh_data()

    async def refresh_data(self) -> None:
        """Refresh alerts and correlation data."""
        if not await is_soc_available():
            self.query_one("#correlation-summary", CorrelationSummary).summary = {}
            return

        # Load correlation summary
        summary = await get_correlation_summary()
        if summary:
            self.query_one("#correlation-summary", CorrelationSummary).summary = summary

        if self.show_threats:
            # Load correlated threats
            threats = await get_correlated_threats(severity=self.severity_filter)
            self.query_one("#threats-table", ThreatsTable).load_threats(threats)
        else:
            # Load alerts
            alerts = await get_alerts(limit=100, severity=self.severity_filter)
            self.query_one("#alerts-table", AlertsTable).load_alerts(alerts)

    def action_refresh(self) -> None:
        """Manual refresh."""
        self.run_worker(self.refresh_data())

    def action_toggle_view(self) -> None:
        """Toggle between alerts and threats view."""
        self.show_threats = not self.show_threats

        alerts_table = self.query_one("#alerts-table")
        threats_table = self.query_one("#threats-table")
        view_label = self.query_one("#view-label", Static)

        if self.show_threats:
            alerts_table.display = False
            threats_table.display = True
            view_label.update("[bold]Correlated Threats[/] (press [cyan]t[/] for alerts view)")
        else:
            alerts_table.display = True
            threats_table.display = False
            view_label.update("[bold]Alerts[/] (press [cyan]t[/] for threats view)")

        self.run_worker(self.refresh_data())

    def action_filter_critical(self) -> None:
        """Filter to critical severity only."""
        self.severity_filter = "critical"
        self.run_worker(self.refresh_data())

    def action_filter_high(self) -> None:
        """Filter to high severity."""
        self.severity_filter = "high"
        self.run_worker(self.refresh_data())

    def action_filter_all(self) -> None:
        """Clear filter."""
        self.severity_filter = None
        self.run_worker(self.refresh_data())
