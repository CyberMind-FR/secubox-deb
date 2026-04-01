"""
SecuBox Console TUI — Main Application
Textual-based terminal dashboard for SecuBox appliances.
"""
from __future__ import annotations
import asyncio
from pathlib import Path

from textual.app import App
from textual.binding import Binding

from .screens import (
    DashboardScreen, ServicesScreen, NetworkScreen, LogsScreen, MenuScreen,
    SOCFleetScreen, SOCAlertsScreen, SOCNodeScreen
)
from .theme import generate_tcss, get_board_name
from .api_client import close_client
from .soc_client import close_soc_client


class SecuBoxConsole(App):
    """SecuBox Console TUI Application."""

    TITLE = "SecuBox Console"
    SUB_TITLE = "Terminal Dashboard"

    # Define CSS using the theme generator
    CSS = generate_tcss()

    # Global key bindings
    BINDINGS = [
        Binding("d", "switch_screen('dashboard')", "Dashboard", show=True),
        Binding("s", "switch_screen('services')", "Services", show=True),
        Binding("n", "switch_screen('network')", "Network", show=True),
        Binding("l", "switch_screen('logs')", "Logs", show=True),
        Binding("m", "switch_screen('menu')", "Menu", show=True),
        Binding("f", "switch_screen('soc_fleet')", "Fleet", show=True),
        Binding("a", "switch_screen('soc_alerts')", "Alerts", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("?", "help", "Help", show=False),
    ]

    SCREENS = {
        "dashboard": DashboardScreen,
        "services": ServicesScreen,
        "network": NetworkScreen,
        "logs": LogsScreen,
        "menu": MenuScreen,
        "soc_fleet": SOCFleetScreen,
        "soc_alerts": SOCAlertsScreen,
        "soc_node": SOCNodeScreen,
    }

    def __init__(self) -> None:
        super().__init__()
        self.title = get_board_name()

    def on_mount(self) -> None:
        """Initialize the app."""
        self.push_screen("dashboard")

    def action_switch_screen(self, screen_name: str) -> None:
        """Switch to a named screen."""
        if screen_name in self.SCREENS:
            self.switch_screen(screen_name)

    def action_help(self) -> None:
        """Show help."""
        self.notify(
            "Keys: d=Dashboard, s=Services, n=Network, l=Logs, m=Menu\n"
            "SOC: f=Fleet, a=Alerts | Navigation: j/k, h=Back, Enter, r=Refresh",
            title="Help",
            timeout=5
        )

    async def on_unmount(self) -> None:
        """Clean up on exit."""
        await close_client()
        await close_soc_client()


def main() -> None:
    """Entry point for the console TUI."""
    app = SecuBoxConsole()
    app.run()


if __name__ == "__main__":
    main()
