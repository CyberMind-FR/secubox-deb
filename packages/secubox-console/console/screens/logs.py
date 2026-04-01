"""
SecuBox Console TUI — Logs Screen
Real-time log viewer with unit filtering.
"""
from __future__ import annotations
import asyncio
import subprocess
from typing import Optional, List

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Label, Select, Switch, RichLog
from textual.containers import Container, Horizontal, Vertical
from textual import work


class LogFilter(Static):
    """Log filter controls."""

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label("Unit:", classes="metric-label")
            yield Select(
                [
                    ("All SecuBox", "secubox*"),
                    ("Hub", "secubox-hub"),
                    ("Portal", "secubox-portal"),
                    ("System", "secubox-system"),
                    ("CrowdSec", "crowdsec"),
                    ("HAProxy", "haproxy"),
                    ("Nginx", "nginx"),
                    ("nftables", "nftables"),
                    ("Kernel", "kernel"),
                    ("All Units", ""),
                ],
                id="unit-select",
                value="secubox*"
            )
            yield Label("Auto-scroll:", classes="metric-label")
            yield Switch(value=True, id="auto-scroll")
            yield Label("Lines: 100", id="line-count", classes="metric-label")


class LogsScreen(Screen):
    """Log viewer screen."""

    BINDINGS = [
        ("d", "switch_screen('dashboard')", "Dashboard"),
        ("s", "switch_screen('services')", "Services"),
        ("n", "switch_screen('network')", "Network"),
        ("l", "switch_screen('logs')", "Logs"),
        ("m", "switch_screen('menu')", "Menu"),
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("c", "clear_logs", "Clear"),
        ("f", "toggle_follow", "Follow"),
        # Vim navigation
        ("j", "scroll_down", "Down"),
        ("k", "scroll_up", "Up"),
        ("g", "scroll_top", "Top"),
        ("G", "scroll_bottom", "Bottom"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._follow_task: Optional[asyncio.Task] = None
        self._following = False
        self._current_unit = "secubox*"

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="logs-container"):
            yield LogFilter(id="log-filter")
            yield RichLog(id="log-view", highlight=True, markup=True)

        yield Footer()

    def on_mount(self) -> None:
        """Load initial logs."""
        self.load_logs()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle unit selection change."""
        if event.select.id == "unit-select":
            self._current_unit = event.value
            self.load_logs()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Handle auto-scroll toggle."""
        if event.switch.id == "auto-scroll":
            log_view = self.query_one("#log-view", RichLog)
            log_view.auto_scroll = event.value

    @work(exclusive=True)
    async def load_logs(self) -> None:
        """Load logs from journalctl."""
        log_view = self.query_one("#log-view", RichLog)
        log_view.clear()

        lines = await self._fetch_logs(self._current_unit, 100)

        for line in lines:
            # Color-code log levels
            if " ERROR " in line or " error " in line or "FAIL" in line:
                log_view.write(f"[red]{line}[/red]")
            elif " WARNING " in line or " warning " in line or " WARN " in line:
                log_view.write(f"[yellow]{line}[/yellow]")
            elif " DEBUG " in line or " debug " in line:
                log_view.write(f"[dim]{line}[/dim]")
            else:
                log_view.write(line)

        # Update line count
        try:
            count_label = self.query_one("#line-count", Label)
            count_label.update(f"Lines: {len(lines)}")
        except Exception:
            pass

    async def _fetch_logs(self, unit: str, lines: int = 100) -> List[str]:
        """Fetch logs from journalctl."""
        cmd = ["journalctl", "--no-pager", "-n", str(lines), "--output=short-iso"]

        if unit:
            if unit == "kernel":
                cmd.append("-k")
            elif "*" in unit:
                # Pattern matching
                cmd.extend(["-u", unit])
            else:
                cmd.extend(["-u", f"{unit}.service"])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")
        except Exception:
            pass

        return ["Error fetching logs"]

    @work(exclusive=True)
    async def start_follow(self) -> None:
        """Start following logs in real-time."""
        self._following = True
        log_view = self.query_one("#log-view", RichLog)

        cmd = ["journalctl", "--no-pager", "-f", "--output=short-iso"]
        if self._current_unit:
            if self._current_unit == "kernel":
                cmd.append("-k")
            else:
                cmd.extend(["-u", self._current_unit])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )

            while self._following:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=1.0
                    )
                    if line:
                        decoded = line.decode().strip()
                        if " ERROR " in decoded or " error " in decoded:
                            log_view.write(f"[red]{decoded}[/red]")
                        elif " WARNING " in decoded or " warning " in decoded:
                            log_view.write(f"[yellow]{decoded}[/yellow]")
                        else:
                            log_view.write(decoded)
                except asyncio.TimeoutError:
                    continue

            process.terminate()

        except Exception:
            self._following = False

    def stop_follow(self) -> None:
        """Stop following logs."""
        self._following = False

    def action_toggle_follow(self) -> None:
        """Toggle log following."""
        if self._following:
            self.stop_follow()
        else:
            self.start_follow()

    def action_clear_logs(self) -> None:
        """Clear the log view."""
        try:
            log_view = self.query_one("#log-view", RichLog)
            log_view.clear()
        except Exception:
            pass

    def action_scroll_down(self) -> None:
        """Scroll down."""
        try:
            log_view = self.query_one("#log-view", RichLog)
            log_view.scroll_down()
        except Exception:
            pass

    def action_scroll_up(self) -> None:
        """Scroll up."""
        try:
            log_view = self.query_one("#log-view", RichLog)
            log_view.scroll_up()
        except Exception:
            pass

    def action_scroll_top(self) -> None:
        """Scroll to top."""
        try:
            log_view = self.query_one("#log-view", RichLog)
            log_view.scroll_home()
        except Exception:
            pass

    def action_scroll_bottom(self) -> None:
        """Scroll to bottom."""
        try:
            log_view = self.query_one("#log-view", RichLog)
            log_view.scroll_end()
        except Exception:
            pass

    def action_refresh(self) -> None:
        """Refresh logs."""
        self.load_logs()

    def action_quit(self) -> None:
        """Quit the application."""
        self.stop_follow()
        self.app.exit()

    def on_unmount(self) -> None:
        """Clean up on unmount."""
        self.stop_follow()
