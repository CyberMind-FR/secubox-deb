"""
SecuBox Console TUI — Metrics Display Widget
"""
from __future__ import annotations
from textual.widgets import Static, ProgressBar, Label
from textual.app import ComposeResult
from textual.containers import Vertical


class MetricDisplay(Static):
    """Display a metric with label and progress bar."""

    def __init__(
        self,
        label: str,
        value: float = 0.0,
        unit: str = "%",
        *,
        id: str | None = None
    ) -> None:
        super().__init__(id=id)
        self._label = label
        self._value = value
        self._unit = unit

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._label, classes="metric-label")
            yield Label(
                f"{self._value:.1f}{self._unit}",
                id=f"{self.id}-value" if self.id else "metric-value",
                classes="metric-value"
            )
            yield ProgressBar(
                total=100,
                show_percentage=False,
                id=f"{self.id}-bar" if self.id else "metric-bar"
            )

    def on_mount(self) -> None:
        self.update_value(self._value)

    def update_value(self, value: float) -> None:
        """Update the metric value."""
        self._value = value
        try:
            value_id = f"#{self.id}-value" if self.id else "#metric-value"
            bar_id = f"#{self.id}-bar" if self.id else "#metric-bar"

            value_label = self.query_one(value_id, Label)
            value_label.update(f"{value:.1f}{self._unit}")

            bar = self.query_one(bar_id, ProgressBar)
            bar.update(progress=value)
        except Exception:
            pass
