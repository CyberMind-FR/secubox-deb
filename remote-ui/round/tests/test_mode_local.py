"""Tests for Local mode display."""
import pytest
from PIL import Image

from agent.display.mode_local import LocalRenderer
from agent.display.renderer import RenderContext


def test_local_renderer_creates_frame():
    """LocalRenderer should create a frame when render() is called."""
    renderer = LocalRenderer()
    ctx = RenderContext(
        mode="local",
        connection_state="disconnected",
        metrics={"cpu": 20, "mem": 45, "disk": 30},
        hostname="eye-remote",
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_local_renderer_initializes():
    """LocalRenderer should initialize with correct dimensions."""
    renderer = LocalRenderer()
    assert renderer.width == 480
    assert renderer.height == 480
    assert renderer.center == (240, 240)


def test_local_renderer_format_uptime_seconds():
    """_format_uptime should format seconds correctly."""
    renderer = LocalRenderer()
    assert renderer._format_uptime(30) == "30s"
    assert renderer._format_uptime(0) == "0s"


def test_local_renderer_format_uptime_minutes():
    """_format_uptime should format minutes correctly."""
    renderer = LocalRenderer()
    assert renderer._format_uptime(60) == "1m"
    assert renderer._format_uptime(300) == "5m"
    assert renderer._format_uptime(3599) == "59m"


def test_local_renderer_format_uptime_hours():
    """_format_uptime should format hours correctly."""
    renderer = LocalRenderer()
    assert renderer._format_uptime(3600) == "1h00m"
    assert renderer._format_uptime(3660) == "1h01m"
    assert renderer._format_uptime(7200) == "2h00m"
    assert renderer._format_uptime(86399) == "23h59m"


def test_local_renderer_format_uptime_days():
    """_format_uptime should format days correctly."""
    renderer = LocalRenderer()
    assert renderer._format_uptime(86400) == "1d0h"
    assert renderer._format_uptime(90000) == "1d1h"
    assert renderer._format_uptime(172800) == "2d0h"
    assert renderer._format_uptime(259200) == "3d0h"


def test_local_renderer_render_with_zero_uptime():
    """LocalRenderer should render with zero uptime."""
    renderer = LocalRenderer()
    ctx = RenderContext(
        mode="local",
        uptime_seconds=0,
        metrics={},
    )
    frame = renderer.render(ctx)
    assert frame is not None
    assert isinstance(frame, Image.Image)


def test_local_renderer_render_with_full_metrics():
    """LocalRenderer should render with all metrics populated."""
    renderer = LocalRenderer()
    ctx = RenderContext(
        mode="local",
        connection_state="disconnected",
        metrics={
            "cpu": 45.2,
            "mem": 62.1,
            "disk": 28.9,
            "wifi": -65,
            "temp": 52.3,
        },
        hostname="secubox-zero",
        uptime_seconds=86400,
    )
    frame = renderer.render(ctx)
    assert frame is not None
    assert isinstance(frame, Image.Image)


def test_local_renderer_render_context_preserved():
    """LocalRenderer should accept various RenderContext states."""
    renderer = LocalRenderer()

    # Test with disconnected state
    ctx1 = RenderContext(
        mode="local",
        connection_state="disconnected",
    )
    frame1 = renderer.render(ctx1)
    assert frame1.size == (480, 480)

    # Test with connected state
    ctx2 = RenderContext(
        mode="local",
        connection_state="connected",
    )
    frame2 = renderer.render(ctx2)
    assert frame2.size == (480, 480)


def test_local_renderer_multiple_renders():
    """LocalRenderer should support multiple sequential renders."""
    renderer = LocalRenderer()

    for i in range(3):
        ctx = RenderContext(
            mode="local",
            uptime_seconds=i * 3600,
            metrics={"cpu": 20 + i * 10},
        )
        frame = renderer.render(ctx)
        assert frame is not None
        assert isinstance(frame, Image.Image)


def test_local_renderer_icons_count():
    """LocalRenderer should have 6 icons defined."""
    from agent.display.mode_local import ICONS

    assert len(ICONS) == 6
    icon_names = [icon["name"] for icon in ICONS]
    expected_names = ["Network", "Power", "Storage", "WiFi", "Settings", "Refresh"]
    assert icon_names == expected_names


def test_local_renderer_icons_have_symbols():
    """LocalRenderer icons should have Unicode symbols."""
    from agent.display.mode_local import ICONS

    for icon in ICONS:
        assert "symbol" in icon
        assert isinstance(icon["symbol"], str)
        assert len(icon["symbol"]) > 0


def test_local_renderer_with_custom_hostname():
    """LocalRenderer should handle custom hostname."""
    renderer = LocalRenderer()
    ctx = RenderContext(
        mode="local",
        hostname="custom-hostname",
        uptime_seconds=3600,
    )
    frame = renderer.render(ctx)
    assert frame is not None


def test_local_renderer_render_is_idempotent():
    """Rendering twice with same context should produce valid output."""
    renderer = LocalRenderer()
    ctx = RenderContext(
        mode="local",
        uptime_seconds=7200,
        metrics={"cpu": 50},
    )

    frame1 = renderer.render(ctx)
    frame2 = renderer.render(ctx)

    assert frame1.size == frame2.size
    assert frame1.mode == frame2.mode
