"""Tests for Gateway mode display."""
import pytest
from PIL import Image

from agent.display.mode_gateway import GatewayRenderer
from agent.display.renderer import RenderContext


def test_gateway_renderer_creates_frame():
    """GatewayRenderer should create a valid frame."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-main', 'online': True},
            {'name': 'secubox-lab', 'online': True},
            {'name': 'secubox-remote', 'online': False},
        ],
        alert_count=1,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_handles_empty_devices():
    """GatewayRenderer should handle empty device list."""
    renderer = GatewayRenderer()
    ctx = RenderContext(mode="gateway", devices=[], alert_count=0)
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_handles_many_devices():
    """GatewayRenderer should handle more than 5 devices (truncate display)."""
    renderer = GatewayRenderer()
    devices = [
        {'name': f'secubox-{i}', 'online': (i % 2 == 0)}
        for i in range(10)
    ]
    ctx = RenderContext(mode="gateway", devices=devices, alert_count=0)
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_all_devices_online():
    """GatewayRenderer should show all devices online."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-1', 'online': True},
            {'name': 'secubox-2', 'online': True},
            {'name': 'secubox-3', 'online': True},
        ],
        alert_count=0,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_all_devices_offline():
    """GatewayRenderer should show all devices offline."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-1', 'online': False},
            {'name': 'secubox-2', 'online': False},
            {'name': 'secubox-3', 'online': False},
        ],
        alert_count=0,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_multiple_alerts():
    """GatewayRenderer should display correct alert count."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-main', 'online': True},
        ],
        alert_count=3,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_single_alert():
    """GatewayRenderer should display singular alert text."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-main', 'online': True},
        ],
        alert_count=1,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_no_alerts():
    """GatewayRenderer should display 'No alerts' when alert_count is 0."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-main', 'online': True},
        ],
        alert_count=0,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_device_with_missing_fields():
    """GatewayRenderer should handle devices with missing fields."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-1'},  # Missing 'online' field
            {'online': True},  # Missing 'name' field
        ],
        alert_count=0,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)


def test_gateway_renderer_inherits_from_display_renderer():
    """GatewayRenderer should inherit from DisplayRenderer."""
    from agent.display.renderer import DisplayRenderer
    renderer = GatewayRenderer()
    assert isinstance(renderer, DisplayRenderer)


def test_gateway_renderer_custom_dimensions():
    """GatewayRenderer should support custom dimensions."""
    renderer = GatewayRenderer(width=320, height=320)
    ctx = RenderContext(mode="gateway", devices=[])
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (320, 320)


def test_gateway_renderer_frame_is_rgb():
    """GatewayRenderer should produce RGB frames."""
    renderer = GatewayRenderer()
    ctx = RenderContext(mode="gateway", devices=[])
    frame = renderer.render(ctx)
    assert frame.mode == 'RGB'


def test_gateway_renderer_with_large_device_name():
    """GatewayRenderer should handle very long device names."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'very-long-device-name-that-exceeds-normal-length', 'online': True},
        ],
        alert_count=0,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)
