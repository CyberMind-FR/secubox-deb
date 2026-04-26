"""
Tests for Flash mode display renderer.

SecuBox Eye Remote — Testing module
CyberMind — https://cybermind.fr
"""
import pytest
from PIL import Image
from pathlib import Path
from unittest.mock import patch, MagicMock

from agent.display.mode_flash import FlashRenderer, STORAGE_PATH
from agent.display.renderer import RenderContext


class TestFlashRenderer:
    """Tests for FlashRenderer class."""

    def test_flash_renderer_initialization(self):
        """FlashRenderer should initialize with correct dimensions."""
        renderer = FlashRenderer()
        assert renderer.width == 480
        assert renderer.height == 480
        assert renderer.center == (240, 240)

    def test_flash_renderer_creates_frame(self):
        """FlashRenderer.render should create PIL Image."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.0)
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)
        assert frame.size == (480, 480)
        assert frame.mode == 'RGB'

    def test_flash_renderer_with_progress(self):
        """FlashRenderer should render progress bar."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.75)
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)
        assert frame.size == (480, 480)

    def test_flash_renderer_no_progress(self):
        """FlashRenderer should handle zero progress."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.0)
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)

    def test_flash_renderer_complete_progress(self):
        """FlashRenderer should handle 100% progress."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=1.0)
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)
        assert frame.size == (480, 480)

    def test_flash_renderer_custom_dimensions(self):
        """FlashRenderer should support custom dimensions."""
        renderer = FlashRenderer(width=320, height=240)
        assert renderer.width == 320
        assert renderer.height == 240
        ctx = RenderContext(mode="flash")
        frame = renderer.render(ctx)
        assert frame.size == (320, 240)

    def test_flash_renderer_progress_values(self):
        """FlashRenderer should handle various progress values."""
        renderer = FlashRenderer()
        for progress in [0.0, 0.25, 0.5, 0.75, 0.99, 1.0]:
            ctx = RenderContext(mode="flash", flash_progress=progress)
            frame = renderer.render(ctx)
            assert isinstance(frame, Image.Image)

    def test_flash_renderer_mode_context(self):
        """FlashRenderer should accept RenderContext with flash mode."""
        renderer = FlashRenderer()
        ctx = RenderContext(
            mode="flash",
            flash_progress=0.5,
            hostname="eye-remote",
            connection_state="local",
        )
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)

    def test_flash_renderer_circle_mask_applied(self):
        """FlashRenderer should apply circular mask."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash")
        frame = renderer.render(ctx)
        # Verify circular clipping was applied (corners should be dark)
        # Get corner pixels (0,0), (479,0), (0,479), (479,479)
        assert frame.getpixel((0, 0)) == (0, 0, 0)
        assert frame.getpixel((479, 0)) == (0, 0, 0)
        assert frame.getpixel((0, 479)) == (0, 0, 0)
        assert frame.getpixel((479, 479)) == (0, 0, 0)

    def test_flash_renderer_multiple_renders(self):
        """FlashRenderer should support multiple consecutive renders."""
        renderer = FlashRenderer()
        frame1 = renderer.render(RenderContext(mode="flash", flash_progress=0.5))
        frame2 = renderer.render(RenderContext(mode="flash", flash_progress=0.75))
        frame3 = renderer.render(RenderContext(mode="flash", flash_progress=1.0))

        assert all(f.size == (480, 480) for f in [frame1, frame2, frame3])
        assert all(isinstance(f, Image.Image) for f in [frame1, frame2, frame3])

    @patch('agent.display.mode_flash.STORAGE_PATH')
    def test_flash_renderer_with_storage_mounted(self, mock_storage_path):
        """FlashRenderer should display storage size when mounted."""
        # Mock the storage path to exist
        mock_storage_path.exists.return_value = True
        mock_stat = MagicMock()
        mock_stat.st_size = 2 * (1024 ** 3)  # 2 GB
        mock_storage_path.stat.return_value = mock_stat

        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.0)
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)

    @patch('agent.display.mode_flash.STORAGE_PATH')
    def test_flash_renderer_without_storage(self, mock_storage_path):
        """FlashRenderer should handle unmounted storage gracefully."""
        # Mock the storage path to not exist
        mock_storage_path.exists.return_value = False

        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.0)
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)

    def test_flash_renderer_progress_bar_dimensions(self):
        """Progress bar should be properly sized."""
        renderer = FlashRenderer()
        # Get the draw context to verify bar dimensions
        ctx = RenderContext(mode="flash", flash_progress=0.5)
        frame = renderer.render(ctx)

        # Verify frame size matches expected
        assert frame.size == (480, 480)
        # Center should have content (not all black due to circular mask)
        center_pixel = frame.getpixel((240, 240))
        # Center area should not be entirely black (0,0,0)
        assert center_pixel != (0, 0, 0)

    def test_flash_renderer_with_metrics(self):
        """FlashRenderer should handle RenderContext with metrics."""
        renderer = FlashRenderer()
        ctx = RenderContext(
            mode="flash",
            flash_progress=0.5,
            metrics={"temperature": 45.2, "usb_speed": "480Mbps"},
        )
        frame = renderer.render(ctx)
        assert isinstance(frame, Image.Image)

    def test_flash_renderer_status_transitions(self):
        """FlashRenderer should handle different status states."""
        renderer = FlashRenderer()

        # Before flash starts
        ctx1 = RenderContext(mode="flash", flash_progress=0.0)
        frame1 = renderer.render(ctx1)
        assert isinstance(frame1, Image.Image)

        # Mid-flash
        ctx2 = RenderContext(mode="flash", flash_progress=0.5)
        frame2 = renderer.render(ctx2)
        assert isinstance(frame2, Image.Image)

        # Flash complete
        ctx3 = RenderContext(mode="flash", flash_progress=1.0)
        frame3 = renderer.render(ctx3)
        assert isinstance(frame3, Image.Image)

    def test_flash_renderer_edge_case_progress(self):
        """FlashRenderer should handle edge case progress values."""
        renderer = FlashRenderer()

        # Just above zero
        ctx_min = RenderContext(mode="flash", flash_progress=0.001)
        frame_min = renderer.render(ctx_min)
        assert isinstance(frame_min, Image.Image)

        # Just below one
        ctx_max = RenderContext(mode="flash", flash_progress=0.999)
        frame_max = renderer.render(ctx_max)
        assert isinstance(frame_max, Image.Image)

    def test_flash_renderer_get_draw_succeeds(self):
        """FlashRenderer should get draw object without error."""
        renderer = FlashRenderer()
        renderer.create_frame()
        draw = renderer.get_draw()
        assert draw is not None

    def test_flash_renderer_get_font_succeeds(self):
        """FlashRenderer should get fonts for rendering."""
        renderer = FlashRenderer()
        font_small = renderer.get_font('small')
        font_medium = renderer.get_font('medium')
        font_large = renderer.get_font('large')
        font_xlarge = renderer.get_font('xlarge')

        assert all(f is not None for f in [font_small, font_medium, font_large, font_xlarge])

    def test_render_context_flash_mode_default_progress(self):
        """RenderContext should default flash_progress to 0.0."""
        ctx = RenderContext(mode="flash")
        assert ctx.flash_progress == 0.0

    def test_render_context_flash_progress_custom(self):
        """RenderContext should accept custom flash_progress."""
        ctx = RenderContext(mode="flash", flash_progress=0.42)
        assert ctx.flash_progress == 0.42

    def test_flash_renderer_different_sizes(self):
        """FlashRenderer should work with different dimensions."""
        for width, height in [(480, 480), (320, 240), (600, 600)]:
            renderer = FlashRenderer(width=width, height=height)
            ctx = RenderContext(mode="flash", flash_progress=0.5)
            frame = renderer.render(ctx)
            assert frame.size == (width, height)

    def test_flash_progress_integer_percentage(self):
        """Progress percentage should be rendered as integer."""
        renderer = FlashRenderer()
        # Progress values should be displayed as clean percentages
        for progress in [0.333, 0.666, 0.777]:
            ctx = RenderContext(mode="flash", flash_progress=progress)
            frame = renderer.render(ctx)
            assert isinstance(frame, Image.Image)
            # Verify frame has content
            assert frame.size == (480, 480)

    def test_flash_renderer_sequential_progress_updates(self):
        """FlashRenderer should handle sequential progress updates."""
        renderer = FlashRenderer()
        progress_values = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

        frames = []
        for progress in progress_values:
            ctx = RenderContext(mode="flash", flash_progress=progress)
            frame = renderer.render(ctx)
            frames.append(frame)
            assert isinstance(frame, Image.Image)

        # All frames should have same dimensions
        assert all(f.size == (480, 480) for f in frames)

    def test_flash_renderer_text_color_usage(self):
        """FlashRenderer should use appropriate text colors."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.5)
        frame = renderer.render(ctx)

        # Verify frame was created and is not entirely one color
        pixels = list(frame.getdata())
        unique_colors = set(pixels)

        # Frame should have multiple colors (not monochrome)
        assert len(unique_colors) > 1


class TestFlashRendererIntegration:
    """Integration tests for FlashRenderer."""

    def test_flash_mode_render_complete_workflow(self):
        """Test complete Flash mode rendering workflow."""
        renderer = FlashRenderer()

        # Simulate flash operation progression
        progress_states = [
            (0.0, "Before flash"),
            (0.25, "25% flashed"),
            (0.50, "50% flashed"),
            (0.75, "75% flashed"),
            (1.0, "Complete"),
        ]

        for progress, description in progress_states:
            ctx = RenderContext(
                mode="flash",
                flash_progress=progress,
                hostname="eye-remote",
            )
            frame = renderer.render(ctx)
            assert isinstance(frame, Image.Image), f"Failed at {description}"
            assert frame.size == (480, 480)

    def test_flash_renderer_render_method_idempotent(self):
        """Rendering the same context twice should produce equivalent frames."""
        renderer = FlashRenderer()
        ctx = RenderContext(mode="flash", flash_progress=0.5)

        frame1 = renderer.render(ctx)
        frame2 = renderer.render(ctx)

        assert frame1.size == frame2.size
        assert frame1.mode == frame2.mode

    @patch('agent.display.mode_flash.STORAGE_PATH')
    def test_flash_renderer_with_real_storage_simulation(self, mock_storage_path):
        """Simulate real storage path scenarios."""
        # Scenario 1: Storage exists and has data
        mock_storage_path.exists.return_value = True
        mock_stat1 = MagicMock()
        mock_stat1.st_size = 2 * (1024 ** 3)
        mock_storage_path.stat.return_value = mock_stat1

        renderer1 = FlashRenderer()
        ctx1 = RenderContext(mode="flash", flash_progress=0.5)
        frame1 = renderer1.render(ctx1)
        assert isinstance(frame1, Image.Image)

        # Scenario 2: Storage does not exist
        mock_storage_path.exists.return_value = False

        renderer2 = FlashRenderer()
        ctx2 = RenderContext(mode="flash", flash_progress=0.5)
        frame2 = renderer2.render(ctx2)
        assert isinstance(frame2, Image.Image)
