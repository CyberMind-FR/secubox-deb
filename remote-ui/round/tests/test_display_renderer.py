"""Tests for display renderer."""
import pytest
from PIL import Image
from agent.display.renderer import DisplayRenderer, RenderContext


def test_render_context_creation():
    """RenderContext should hold display state."""
    ctx = RenderContext(
        width=480,
        height=480,
        mode="dashboard",
        connection_state="connected",
    )
    assert ctx.width == 480
    assert ctx.height == 480
    assert ctx.mode == "dashboard"


def test_render_context_defaults():
    """RenderContext should have sensible defaults."""
    ctx = RenderContext()
    assert ctx.width == 480
    assert ctx.height == 480
    assert ctx.mode == "local"
    assert ctx.connection_state == "disconnected"
    assert ctx.hostname == "eye-remote"
    assert ctx.uptime_seconds == 0
    assert ctx.alert_count == 0
    assert ctx.flash_progress == 0.0
    assert ctx.devices == []
    assert ctx.metrics == {}


def test_display_renderer_creates_image():
    """DisplayRenderer should create PIL Image."""
    renderer = DisplayRenderer(width=480, height=480)
    img = renderer.create_frame()
    assert isinstance(img, Image.Image)
    assert img.size == (480, 480)
    assert img.mode == 'RGB'


def test_display_renderer_default_size():
    """DisplayRenderer should use 480x480 by default."""
    renderer = DisplayRenderer()
    assert renderer.width == 480
    assert renderer.height == 480


def test_display_renderer_center():
    """DisplayRenderer should calculate center point."""
    renderer = DisplayRenderer()
    assert renderer.center == (240, 240)


def test_display_renderer_get_draw():
    """get_draw should return ImageDraw object."""
    renderer = DisplayRenderer()
    draw = renderer.get_draw()
    assert draw is not None


def test_display_renderer_get_font():
    """get_font should return a font."""
    renderer = DisplayRenderer()
    font = renderer.get_font('medium')
    assert font is not None


def test_display_renderer_get_font_fallback():
    """get_font should return default for missing size."""
    renderer = DisplayRenderer()
    font = renderer.get_font('nonexistent')
    assert font is not None


def test_display_renderer_draw_text_centered():
    """draw_text_centered should place text at center of frame."""
    renderer = DisplayRenderer()
    draw = renderer.get_draw()
    # Should not raise exception
    renderer.draw_text_centered(draw, "Test", 240)


def test_display_renderer_multiple_frames():
    """DisplayRenderer should support creating multiple frames."""
    renderer = DisplayRenderer()
    frame1 = renderer.create_frame()
    frame2 = renderer.create_frame()
    assert frame1 is not None
    assert frame2 is not None
    assert frame1.size == frame2.size


def test_display_renderer_custom_dimensions():
    """DisplayRenderer should support custom dimensions."""
    renderer = DisplayRenderer(width=320, height=240)
    assert renderer.width == 320
    assert renderer.height == 240
    assert renderer.center == (160, 120)
    img = renderer.create_frame()
    assert img.size == (320, 240)


def test_render_context_with_metrics():
    """RenderContext should accept metrics dict."""
    metrics = {"cpu": 45.5, "memory": 78.2, "uptime": 3600}
    ctx = RenderContext(metrics=metrics)
    assert ctx.metrics == metrics


def test_render_context_with_devices():
    """RenderContext should accept device list."""
    devices = ["device1", "device2"]
    ctx = RenderContext(devices=devices)
    assert ctx.devices == devices


def test_display_renderer_colors_defined():
    """DisplayRenderer should have module colors available."""
    from agent.display.renderer import MODULE_COLORS, STATUS_OK, STATUS_ERROR

    assert 'AUTH' in MODULE_COLORS
    assert 'WALL' in MODULE_COLORS
    assert 'BOOT' in MODULE_COLORS
    assert 'MIND' in MODULE_COLORS
    assert 'ROOT' in MODULE_COLORS
    assert 'MESH' in MODULE_COLORS

    assert STATUS_OK == (0, 255, 65)
    assert STATUS_ERROR == (255, 0, 80)


def test_display_renderer_rgb565_conversion():
    """_convert_to_rgb565 should convert RGB to RGB565 format."""
    renderer = DisplayRenderer(width=2, height=2)
    # Create test image with known colors
    img = Image.new('RGB', (2, 2), (255, 0, 0))  # Red
    rgb565 = renderer._convert_to_rgb565(img)

    # Should have 4 pixels * 2 bytes each = 8 bytes
    assert len(rgb565) == 8
    assert isinstance(rgb565, bytes)
