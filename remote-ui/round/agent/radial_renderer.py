"""
SecuBox-Deb :: Eye Remote - Radial Menu Renderer

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

Renders radial menus on 480x480 circular display using Pillow.
"""
import logging
import math
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw, ImageFont

from menu_navigator import MenuState, MenuMode
from menu_definitions import MENUS

logger = logging.getLogger(__name__)

# Display constants
WIDTH = 480
HEIGHT = 480
CENTER_X = WIDTH // 2
CENTER_Y = HEIGHT // 2

# Radial menu geometry
OUTER_RADIUS = 220
INNER_RADIUS = 80
SLICE_ANGLE = 60  # 360 / 6 slices

# Slice colors (matching the spec)
SLICE_COLORS = [
    "#C04E24",  # Slice 0 (top-right)
    "#9A6010",  # Slice 1
    "#803018",  # Slice 2 (bottom-right)
    "#3D35A0",  # Slice 3 (bottom-left)
    "#0A5840",  # Slice 4
    "#104A88",  # Slice 5 (top-left)
]

# Colors
BG_COLOR = "#0a0a0f"  # cosmos-black
CENTER_COLOR = "#1a1a2e"
TEXT_COLOR = "#e8e6d9"
HIGHLIGHT_COLOR = "#00ff41"  # matrix-green


class RadialRenderer:
    """Renders radial menus to 480x480 circular display."""

    def __init__(self):
        """Initialize renderer."""
        self.width = WIDTH
        self.height = HEIGHT
        self.canvas = None
        self.draw = None

        # Try to load fonts
        self.font_title = self._load_font(24)
        self.font_label = self._load_font(16)
        self.font_small = self._load_font(12)

    def _load_font(self, size: int) -> ImageFont.FreeTypeFont:
        """Load font or fall back to default."""
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        ]

        for path in font_paths:
            if Path(path).exists():
                try:
                    return ImageFont.truetype(path, size)
                except Exception as e:
                    logger.warning(f"Failed to load font {path}: {e}")

        return ImageFont.load_default()

    def get_slice_angles(self, index: int) -> dict:
        """
        Calculate start/end angles for a slice.

        Args:
            index: Slice index (0-5)

        Returns:
            Dict with 'start' and 'end' angles in degrees
        """
        # Slice 0 is at top-right (0 degrees center)
        # Each slice is 60 degrees (360/6)
        # Angles go counter-clockwise
        # Slice 0: -30 to 30, Slice 1: 30 to 90, etc.
        start_angle = -30 + (index * SLICE_ANGLE)
        end_angle = start_angle + SLICE_ANGLE
        return {
            'start': start_angle,
            'end': end_angle
        }

    def _draw_slice(
        self,
        index: int,
        label: str,
        is_selected: bool = False,
        is_enabled: bool = True
    ):
        """
        Draw a radial menu slice.

        Args:
            index: Slice index (0-5)
            label: Text label
            is_selected: Highlight this slice
            is_enabled: Slice is active
        """
        angles = self.get_slice_angles(index)

        # Base color
        color = SLICE_COLORS[index] if is_enabled else "#2a2a3a"

        # Highlight if selected
        if is_selected and is_enabled:
            # Draw outer highlight ring
            bbox = [
                CENTER_X - OUTER_RADIUS - 5,
                CENTER_Y - OUTER_RADIUS - 5,
                CENTER_X + OUTER_RADIUS + 5,
                CENTER_Y + OUTER_RADIUS + 5
            ]
            self.draw.pieslice(
                bbox,
                start=angles['start'],
                end=angles['end'],
                fill=HIGHLIGHT_COLOR,
                outline=HIGHLIGHT_COLOR,
                width=3
            )

        # Draw main slice
        bbox = [
            CENTER_X - OUTER_RADIUS,
            CENTER_Y - OUTER_RADIUS,
            CENTER_X + OUTER_RADIUS,
            CENTER_Y + OUTER_RADIUS
        ]
        self.draw.pieslice(
            bbox,
            start=angles['start'],
            end=angles['end'],
            fill=color,
            outline="#1a1a2e",
            width=2
        )

        # Cut out center circle
        center_bbox = [
            CENTER_X - INNER_RADIUS,
            CENTER_Y - INNER_RADIUS,
            CENTER_X + INNER_RADIUS,
            CENTER_Y + INNER_RADIUS
        ]
        self.draw.ellipse(center_bbox, fill=BG_COLOR, outline="#1a1a2e", width=2)

        # Draw label
        if label:
            # Calculate label position (middle of slice arc)
            center_angle = (angles['start'] + angles['end']) / 2
            label_radius = (OUTER_RADIUS + INNER_RADIUS) / 2

            angle_rad = math.radians(center_angle)
            label_x = CENTER_X + int(label_radius * math.cos(angle_rad))
            label_y = CENTER_Y - int(label_radius * math.sin(angle_rad))

            text_color = TEXT_COLOR if is_enabled else "#4a4a5a"

            # Get text bounding box for centering
            bbox = self.draw.textbbox((0, 0), label, font=self.font_label)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]

            self.draw.text(
                (label_x - text_width // 2, label_y - text_height // 2),
                label,
                fill=text_color,
                font=self.font_label
            )

    def _draw_center(self, title: str):
        """
        Draw center circle with title.

        Args:
            title: Menu title text
        """
        # Draw center circle
        center_bbox = [
            CENTER_X - INNER_RADIUS,
            CENTER_Y - INNER_RADIUS,
            CENTER_X + INNER_RADIUS,
            CENTER_Y + INNER_RADIUS
        ]
        self.draw.ellipse(center_bbox, fill=CENTER_COLOR, outline="#00d4ff", width=2)

        # Draw title text
        bbox = self.draw.textbbox((0, 0), title, font=self.font_title)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        self.draw.text(
            (CENTER_X - text_width // 2, CENTER_Y - text_height // 2),
            title,
            fill=TEXT_COLOR,
            font=self.font_title
        )

    def render(self, state: MenuState) -> Image.Image:
        """
        Render menu state to image.

        Args:
            state: Current menu state

        Returns:
            PIL Image (480x480)
        """
        # Create new canvas
        self.canvas = Image.new('RGB', (self.width, self.height), BG_COLOR)
        self.draw = ImageDraw.Draw(self.canvas)

        # Get current menu definition (returns list of MenuItem)
        menu_items = MENUS.get(state.current_menu)
        if not menu_items:
            logger.warning(f"Menu {state.current_menu} not found")
            return self.canvas

        # Draw slices
        for i, item in enumerate(menu_items):
            is_selected = (i == state.selected_index)
            # MenuItem has 'enabled' attribute, default to True if not present
            is_enabled = getattr(item, 'enabled', True)
            self._draw_slice(i, item.label, is_selected, is_enabled)

        # Draw center with menu ID as title
        menu_title = state.current_menu.name.replace('_', ' ')
        self._draw_center(menu_title)

        return self.canvas

    def write_to_framebuffer(self, fb_path: str = "/dev/fb0"):
        """
        Write rendered image to framebuffer.

        Args:
            fb_path: Path to framebuffer device
        """
        if not self.canvas:
            logger.error("No canvas to write")
            return

        try:
            # Get framebuffer info from sysfs
            try:
                with open('/sys/class/graphics/fb0/bits_per_pixel', 'r') as f:
                    bpp = int(f.read().strip())
            except Exception:
                bpp = 16  # Default for HyperPixel

            try:
                with open('/sys/class/graphics/fb0/virtual_size', 'r') as f:
                    vsize = f.read().strip().split(',')
                    fb_width = int(vsize[0])
                    fb_height = int(vsize[1]) if len(vsize) > 1 else fb_width
            except Exception:
                fb_width, fb_height = 480, 480

            logger.info(f"Framebuffer: {fb_width}x{fb_height} @ {bpp}bpp")

            # Resize if needed
            img = self.canvas
            if img.size != (fb_width, fb_height):
                img = img.resize((fb_width, fb_height))

            if bpp == 32:
                # 32-bit BGRA
                pixels = img.convert('RGBA')
                raw = pixels.tobytes('raw', 'BGRA')
            elif bpp == 24:
                # 24-bit BGR
                pixels = img.convert('RGB')
                raw = pixels.tobytes('raw', 'BGR')
            elif bpp == 16:
                # 16-bit RGB565
                rgb_img = img.convert('RGB')
                pixel_data = rgb_img.load()
                data = bytearray(fb_width * fb_height * 2)
                idx = 0
                for y in range(fb_height):
                    for x in range(fb_width):
                        r, g, b = pixel_data[x, y]  # type: ignore
                        # RGB565: RRRRRGGG GGGBBBBB (little endian)
                        pixel = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                        data[idx] = pixel & 0xFF
                        data[idx + 1] = (pixel >> 8) & 0xFF
                        idx += 2
                raw = bytes(data)
            else:
                # Fallback: raw RGB
                raw = img.convert('RGB').tobytes()

            with open(fb_path, 'wb') as fb:
                fb.write(raw)

            logger.debug(f"Wrote {len(raw)} bytes to {fb_path}")

        except Exception as e:
            logger.error(f"Failed to write to framebuffer: {e}")
            import traceback
            logger.error(traceback.format_exc())
