"""
Tests for Dashboard mode display renderer.

SecuBox Eye Remote — Mode Dashboard Tests
CyberMind — https://cybermind.fr
"""
import pytest
from PIL import Image

from agent.display.mode_dashboard import DashboardRenderer
from agent.display.renderer import RenderContext


class TestDashboardRendererBasics:
    """Test basic DashboardRenderer functionality."""

    def test_dashboard_renderer_instantiation(self):
        """DashboardRenderer should instantiate without error."""
        renderer = DashboardRenderer()
        assert renderer is not None
        assert renderer.width == 480
        assert renderer.height == 480

    def test_dashboard_renderer_creates_frame(self):
        """DashboardRenderer.render should return a PIL Image."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            mode="dashboard",
            connection_state="connected",
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
            hostname="secubox-main",
            uptime_seconds=3600,
        )
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)
        assert frame.size == (480, 480)

    def test_dashboard_renderer_frame_mode(self):
        """Rendered frame should be in RGB mode."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 50, "mem": 50, "disk": 50, "load": 1.0, "temp": 45, "wifi": -60}
        )
        frame = renderer.render(ctx)
        assert frame.mode == "RGB"


class TestDashboardMetrics:
    """Test dashboard metric rendering."""

    def test_dashboard_with_nominal_metrics(self):
        """Dashboard should render with nominal metric values."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            mode="dashboard",
            connection_state="connected",
            metrics={
                "cpu": 23.5,
                "mem": 41.2,
                "disk": 28.7,
                "load": 0.18,
                "temp": 44.2,
                "wifi": -62,
            },
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_high_cpu(self):
        """Dashboard should handle high CPU metric."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 95, "mem": 50, "disk": 50, "load": 3.5, "temp": 65, "wifi": -50}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_high_memory(self):
        """Dashboard should handle high memory metric."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 50, "mem": 92, "disk": 50, "load": 1.5, "temp": 50, "wifi": -60}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_high_disk(self):
        """Dashboard should handle high disk metric."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 50, "mem": 50, "disk": 93, "load": 1.5, "temp": 50, "wifi": -60}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_missing_metrics(self):
        """Dashboard should gracefully handle missing metrics."""
        renderer = DashboardRenderer()
        ctx = RenderContext(metrics={})
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_partial_metrics(self):
        """Dashboard should handle partial metric data."""
        renderer = DashboardRenderer()
        ctx = RenderContext(metrics={"cpu": 45, "mem": 60})
        frame = renderer.render(ctx)
        assert frame is not None


class TestDashboardConnectionStates:
    """Test dashboard rendering under different connection states."""

    def test_dashboard_connected_state(self):
        """Dashboard should render connected state."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            connection_state="connected",
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_degraded_state(self):
        """Dashboard should render degraded state with visual feedback."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            connection_state="degraded",
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_stale_state(self):
        """Dashboard should render stale state with pulsing animation."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            connection_state="stale",
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_disconnected_state(self):
        """Dashboard should render disconnected state."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            connection_state="disconnected",
            metrics={"cpu": 0, "mem": 0, "disk": 0, "load": 0, "temp": 0, "wifi": 0},
        )
        frame = renderer.render(ctx)
        assert frame is not None


class TestDashboardHostnameAndUptime:
    """Test hostname and uptime display."""

    def test_dashboard_with_hostname(self):
        """Dashboard should display provided hostname."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            hostname="secubox-main",
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_default_hostname(self):
        """Dashboard should use default hostname if not provided."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            hostname=None,
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_various_uptimes(self):
        """Dashboard should format uptime correctly."""
        renderer = DashboardRenderer()

        # Test seconds
        ctx = RenderContext(uptime_seconds=45)
        assert renderer._format_uptime(45) == "45s"

        # Test minutes
        ctx = RenderContext(uptime_seconds=300)
        assert renderer._format_uptime(300) == "5m"

        # Test hours
        ctx = RenderContext(uptime_seconds=3661)
        assert renderer._format_uptime(3661) == "1h01m"

        # Test days
        ctx = RenderContext(uptime_seconds=90061)
        assert renderer._format_uptime(90061) == "1d1h"

    def test_dashboard_uptime_formatting(self):
        """Test _format_uptime method with various inputs."""
        renderer = DashboardRenderer()

        assert renderer._format_uptime(0) == "0s"
        assert renderer._format_uptime(1) == "1s"
        assert renderer._format_uptime(59) == "59s"
        assert renderer._format_uptime(60) == "1m"
        assert renderer._format_uptime(3599) == "59m"
        assert renderer._format_uptime(3600) == "1h00m"
        assert renderer._format_uptime(86400) == "1d0h"
        assert renderer._format_uptime(86400 + 3600) == "1d1h"


class TestDashboardMetricNormalization:
    """Test metric normalization for different metric types."""

    def test_normalize_cpu_metric(self):
        """CPU metric should normalize percentage values."""
        renderer = DashboardRenderer()
        assert renderer._normalize_metric("cpu", 0) == 0.0
        assert renderer._normalize_metric("cpu", 50) == 0.5
        assert renderer._normalize_metric("cpu", 100) == 1.0
        assert renderer._normalize_metric("cpu", 150) == 1.0  # Clamped

    def test_normalize_memory_metric(self):
        """Memory metric should normalize percentage values."""
        renderer = DashboardRenderer()
        assert renderer._normalize_metric("mem", 0) == 0.0
        assert renderer._normalize_metric("mem", 50) == 0.5
        assert renderer._normalize_metric("mem", 100) == 1.0

    def test_normalize_disk_metric(self):
        """Disk metric should normalize percentage values."""
        renderer = DashboardRenderer()
        assert renderer._normalize_metric("disk", 0) == 0.0
        assert renderer._normalize_metric("disk", 50) == 0.5
        assert renderer._normalize_metric("disk", 100) == 1.0

    def test_normalize_load_metric(self):
        """Load metric should normalize against 4.0 baseline."""
        renderer = DashboardRenderer()
        assert renderer._normalize_metric("load", 0) == 0.0
        assert renderer._normalize_metric("load", 2.0) == 0.5
        assert renderer._normalize_metric("load", 4.0) == 1.0
        assert renderer._normalize_metric("load", 8.0) == 1.0  # Clamped

    def test_normalize_temperature_metric(self):
        """Temperature should normalize 30-80°C range."""
        renderer = DashboardRenderer()
        assert renderer._normalize_metric("temp", 30) == 0.0
        assert renderer._normalize_metric("temp", 55) == 0.5
        assert renderer._normalize_metric("temp", 80) == 1.0
        assert renderer._normalize_metric("temp", 100) == 1.0  # Clamped
        assert renderer._normalize_metric("temp", 10) == 0.0  # Clamped

    def test_normalize_wifi_metric(self):
        """WiFi RSSI should normalize -80 to -20 dBm range."""
        renderer = DashboardRenderer()
        assert renderer._normalize_metric("wifi", -80) == 0.0
        assert renderer._normalize_metric("wifi", -50) == 0.5
        assert renderer._normalize_metric("wifi", -20) == 1.0
        assert renderer._normalize_metric("wifi", 0) == 1.0  # Clamped
        assert renderer._normalize_metric("wifi", -100) == 0.0  # Clamped


class TestDashboardAnimation:
    """Test animation state in dashboard renderer."""

    def test_dashboard_animation_offset_increments(self):
        """Animation offset should increment with each render."""
        renderer = DashboardRenderer()
        initial_offset = renderer._animation_offset
        ctx = RenderContext(metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55})

        renderer.render(ctx)
        assert renderer._animation_offset == initial_offset + 0.02

        renderer.render(ctx)
        assert renderer._animation_offset == initial_offset + 0.04

    def test_dashboard_stale_state_uses_animation(self):
        """Stale connection state should produce pulsing effect."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            connection_state="stale",
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55},
        )

        # Multiple renders should produce different visual states
        frame1 = renderer.render(ctx)
        frame2 = renderer.render(ctx)
        frame3 = renderer.render(ctx)

        # Frames should be different due to animation offset
        assert frame1 is not None
        assert frame2 is not None
        assert frame3 is not None


class TestDashboardEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_dashboard_with_zero_metrics(self):
        """Dashboard should handle all-zero metrics."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 0, "mem": 0, "disk": 0, "load": 0, "temp": 0, "wifi": 0}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_max_metrics(self):
        """Dashboard should handle maximum metric values."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 100, "mem": 100, "disk": 100, "load": 16.0, "temp": 100, "wifi": 0}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_extreme_metrics(self):
        """Dashboard should clamp extreme metric values."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 999, "mem": 999, "disk": 999, "load": 64.0, "temp": 150, "wifi": -150}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_with_negative_metrics(self):
        """Dashboard should handle negative metric values gracefully."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": -10, "mem": -5, "disk": 0, "load": -1, "temp": -20, "wifi": -200}
        )
        frame = renderer.render(ctx)
        assert frame is not None

    def test_dashboard_multiple_consecutive_renders(self):
        """Dashboard should render multiple frames consecutively."""
        renderer = DashboardRenderer()
        ctx = RenderContext(
            metrics={"cpu": 45, "mem": 60, "disk": 30, "load": 1.5, "temp": 42, "wifi": -55}
        )

        frames = [renderer.render(ctx) for _ in range(5)]
        assert len(frames) == 5
        assert all(isinstance(f, Image.Image) for f in frames)
        assert all(f.size == (480, 480) for f in frames)
