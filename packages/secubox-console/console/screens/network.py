"""
SecuBox Console TUI — Network Screen
Network interface status and configuration.
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import Dict, List

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, DataTable, Static, Label
from textual.containers import Container, Horizontal, Vertical
from textual import work

from ..api_client import get_client
from secubox_core.kiosk import (
    get_physical_interfaces,
    get_interface_classification,
    check_interface_carrier,
    detect_board_type
)


class NetworkModeCard(Static):
    """Card showing current network mode."""

    def compose(self) -> ComposeResult:
        yield Label("Network Mode", classes="card-title")
        yield Label("Detecting...", id="network-mode", classes="metric-value")
        yield Label("", id="network-desc", classes="metric-label")

    def update_mode(self, mode: str, description: str = "") -> None:
        try:
            mode_label = self.query_one("#network-mode", Label)
            desc_label = self.query_one("#network-desc", Label)
            mode_label.update(mode.upper())
            desc_label.update(description)
        except Exception:
            pass


class InterfaceSummary(Static):
    """Summary of interface classification."""

    def compose(self) -> ComposeResult:
        yield Label("Interface Classification", classes="card-title")
        with Horizontal():
            yield Label("WAN: --", id="wan-count", classes="metric-value")
            yield Label("LAN: --", id="lan-count", classes="metric-value")
            yield Label("SFP: --", id="sfp-count", classes="metric-value")

    def update_counts(self, wan: int, lan: int, sfp: int) -> None:
        try:
            self.query_one("#wan-count", Label).update(f"WAN: {wan}")
            self.query_one("#lan-count", Label).update(f"LAN: {lan}")
            self.query_one("#sfp-count", Label).update(f"SFP: {sfp}")
        except Exception:
            pass


class NetworkScreen(Screen):
    """Network interface status screen."""

    BINDINGS = [
        ("d", "switch_screen('dashboard')", "Dashboard"),
        ("s", "switch_screen('services')", "Services"),
        ("n", "switch_screen('network')", "Network"),
        ("l", "switch_screen('logs')", "Logs"),
        ("m", "switch_screen('menu')", "Menu"),
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        # Vim navigation
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="network-container"):
            with Horizontal(id="network-top"):
                yield NetworkModeCard(id="mode-card")
                yield InterfaceSummary(id="summary-card")

            yield Label("Network Interfaces", classes="card-title")
            yield DataTable(id="interfaces-table")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize and load data."""
        table = self.query_one("#interfaces-table", DataTable)
        table.add_columns("Interface", "Type", "State", "IP Address", "Speed", "Carrier")
        table.cursor_type = "row"
        table.zebra_stripes = True

        self.refresh_network()

    @work(exclusive=True)
    async def refresh_network(self) -> None:
        """Refresh network interface data."""
        # Get interface classification
        board_type = detect_board_type()
        classification = get_interface_classification(board_type)

        wan_list = classification.get("wan", [])
        lan_list = classification.get("lan", [])
        sfp_list = classification.get("sfp", [])

        # Update summary
        try:
            summary = self.query_one("#summary-card", InterfaceSummary)
            summary.update_counts(len(wan_list), len(lan_list), len(sfp_list))
        except Exception:
            pass

        # Get network mode
        mode_info = await self._get_network_mode()
        try:
            mode_card = self.query_one("#mode-card", NetworkModeCard)
            mode_card.update_mode(
                mode_info.get("mode", "unknown"),
                mode_info.get("description", "")
            )
        except Exception:
            pass

        # Build interface list with details
        interfaces = []
        all_ifaces = set(wan_list + lan_list + sfp_list)

        # Also include any physical interfaces not classified
        for iface in get_physical_interfaces():
            all_ifaces.add(iface)

        for iface in sorted(all_ifaces):
            iface_type = "WAN" if iface in wan_list else \
                         "LAN" if iface in lan_list else \
                         "SFP" if iface in sfp_list else "Other"

            state = self._get_interface_state(iface)
            ip = self._get_interface_ip(iface)
            speed = self._get_interface_speed(iface)
            carrier = "UP" if check_interface_carrier(iface) else "DOWN"

            interfaces.append({
                "name": iface,
                "type": iface_type,
                "state": state,
                "ip": ip,
                "speed": speed,
                "carrier": carrier
            })

        self._update_table(interfaces)

    async def _get_network_mode(self) -> Dict:
        """Get current network mode from API or netplan."""
        client = get_client()
        mode_data = await client.network_mode()

        if mode_data and mode_data.get("mode"):
            return mode_data

        # Fall back to detecting from netplan
        mode = "unknown"
        desc = ""

        netplan_dir = Path("/etc/netplan")
        if netplan_dir.exists():
            for f in netplan_dir.glob("*.yaml"):
                try:
                    content = f.read_text()
                    if "bridges:" in content:
                        mode = "bridge"
                        desc = "Inline bridge/sniffer mode"
                    elif "vlans:" in content:
                        mode = "router"
                        desc = "Router with VLANs"
                    elif "dhcp4: true" in content:
                        mode = "dhcp"
                        desc = "DHCP client mode"
                except Exception:
                    pass

        return {"mode": mode, "description": desc}

    def _get_interface_state(self, iface: str) -> str:
        """Get interface operstate."""
        state_path = Path(f"/sys/class/net/{iface}/operstate")
        if state_path.exists():
            try:
                return state_path.read_text().strip()
            except Exception:
                pass
        return "unknown"

    def _get_interface_ip(self, iface: str) -> str:
        """Get interface IP address."""
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "inet " in line:
                        # Extract IP/CIDR
                        parts = line.strip().split()
                        for i, p in enumerate(parts):
                            if p == "inet" and i + 1 < len(parts):
                                return parts[i + 1]
        except Exception:
            pass
        return "-"

    def _get_interface_speed(self, iface: str) -> str:
        """Get interface speed."""
        speed_path = Path(f"/sys/class/net/{iface}/speed")
        if speed_path.exists():
            try:
                speed = int(speed_path.read_text().strip())
                if speed >= 1000:
                    return f"{speed // 1000}G"
                elif speed > 0:
                    return f"{speed}M"
            except Exception:
                pass
        return "-"

    def _update_table(self, interfaces: List[Dict]) -> None:
        """Update the interfaces table."""
        try:
            table = self.query_one("#interfaces-table", DataTable)
            table.clear()

            for iface in interfaces:
                table.add_row(
                    iface["name"],
                    iface["type"],
                    iface["state"],
                    iface["ip"],
                    iface["speed"],
                    iface["carrier"]
                )
        except Exception:
            pass

    def action_cursor_down(self) -> None:
        """Move cursor down."""
        try:
            table = self.query_one("#interfaces-table", DataTable)
            table.action_cursor_down()
        except Exception:
            pass

    def action_cursor_up(self) -> None:
        """Move cursor up."""
        try:
            table = self.query_one("#interfaces-table", DataTable)
            table.action_cursor_up()
        except Exception:
            pass

    def action_refresh(self) -> None:
        """Manual refresh."""
        self.refresh_network()

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()
