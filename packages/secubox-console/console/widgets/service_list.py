"""
SecuBox Console TUI — Service List Widget
"""
from __future__ import annotations
from typing import List, Dict
from textual.widgets import Static, DataTable
from textual.app import ComposeResult


class ServiceListWidget(Static):
    """Widget displaying a list of services."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self._services: List[Dict] = []

    def compose(self) -> ComposeResult:
        yield DataTable(id=f"{self.id}-table" if self.id else "services-table")

    def on_mount(self) -> None:
        table_id = f"#{self.id}-table" if self.id else "#services-table"
        table = self.query_one(table_id, DataTable)
        table.add_columns("Service", "Status")
        table.cursor_type = "row"

    def update_services(self, services: List[Dict]) -> None:
        """Update the service list."""
        self._services = services
        try:
            table_id = f"#{self.id}-table" if self.id else "#services-table"
            table = self.query_one(table_id, DataTable)
            table.clear()

            for svc in services:
                name = svc.get("name", "unknown")
                status = svc.get("status", svc.get("active", "unknown"))
                table.add_row(name, status)
        except Exception:
            pass

    def get_selected(self) -> str | None:
        """Get the currently selected service name."""
        try:
            table_id = f"#{self.id}-table" if self.id else "#services-table"
            table = self.query_one(table_id, DataTable)
            if table.cursor_row is not None and table.cursor_row < len(self._services):
                return self._services[table.cursor_row].get("name")
        except Exception:
            pass
        return None
