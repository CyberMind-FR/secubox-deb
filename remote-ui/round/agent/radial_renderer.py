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
    """Renders radial menus and dashboard to 480x480 circular display."""

    ICON_SIZE = 40  # Icon size in pixels

    def __init__(self):
        """Initialize renderer."""
        self.width = WIDTH
        self.height = HEIGHT
        self.canvas = None
        self.draw = None

        # Metrics storage for dashboard display
        self.metrics: dict = {}

        # Icon cache
        self._icon_cache: dict[str, Image.Image] = {}

        # Icon directories - use absolute paths only
        self.icon_dir = Path("/usr/lib/secubox-eye/assets/icons")

        # Verify icon directory exists and has icons
        if self.icon_dir.exists():
            icons = list(self.icon_dir.glob("*.png"))
            logger.info(f"Icon directory: {self.icon_dir} ({len(icons)} icons)")
            if icons:
                logger.info(f"Sample icons: {[i.name for i in icons[:5]]}")
        else:
            logger.error(f"ICON DIRECTORY NOT FOUND: {self.icon_dir}")

        # Try to load fonts
        self.font_title = self._load_font(24)
        self.font_label = self._load_font(14)  # Smaller for icon + label
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

    def _load_icon(self, name: str) -> Optional[Image.Image]:
        """
        Load and cache an icon by name.
        Icons are converted to white using their alpha as mask.

        Args:
            name: Icon name without extension (e.g., "devices")

        Returns:
            PIL Image or None if not found
        """
        if not name:
            return None

        if name in self._icon_cache:
            return self._icon_cache[name]

        # Try sizes: 48px preferred, then 22px, then 96px
        for size in [48, 22, 96]:
            icon_path = self.icon_dir / f"{name}-{size}.png"
            if icon_path.exists():
                try:
                    icon = Image.open(icon_path).convert("RGBA")
                    resample = getattr(Image, 'Resampling', Image).LANCZOS
                    icon = icon.resize((self.ICON_SIZE, self.ICON_SIZE), resample)

                    # Icons are colored shapes - just use original with alpha
                    # The slice colors are different enough for contrast
                    pass  # Keep original RGBA icon as-is

                    self._icon_cache[name] = icon
                    logger.info(f"Loaded: {name}")
                    return icon
                except Exception as e:
                    logger.error(f"Icon load failed {icon_path}: {e}")
                    return None

        logger.error(f"Icon not found: {name}")
        return None

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
        icon_name: Optional[str] = None,
        is_selected: bool = False,
        is_enabled: bool = True
    ):
        """
        Draw a radial menu slice with optional icon.

        Args:
            index: Slice index (0-5)
            label: Text label
            icon_name: Icon name to display (optional)
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

        # Calculate radial positions for icon and label
        center_angle = (angles['start'] + angles['end']) / 2
        angle_rad = math.radians(center_angle)

        # Icon at outer radius, label at inner radius (both radial)
        icon_radius = (OUTER_RADIUS + INNER_RADIUS) / 2 + 15  # Towards outer edge
        label_radius = (OUTER_RADIUS + INNER_RADIUS) / 2 - 15  # Towards inner edge

        text_color = TEXT_COLOR if is_enabled else "#4a4a5a"

        # Load and draw icon if available
        icon = self._load_icon(icon_name) if icon_name else None
        if icon and self.canvas:
            # Position icon radially (further from center)
            icon_cx = CENTER_X + int(icon_radius * math.cos(angle_rad))
            icon_cy = CENTER_Y - int(icon_radius * math.sin(angle_rad))
            icon_x = icon_cx - self.ICON_SIZE // 2
            icon_y = icon_cy - self.ICON_SIZE // 2
            self.canvas.paste(icon, (icon_x, icon_y), icon)  # Use alpha mask
            logger.debug(f"Icon '{icon_name}' at ({icon_x}, {icon_y})")

        # Draw label radially (closer to center than icon)
        if label:
            # Use label radius if icon present, otherwise use middle radius
            actual_label_radius = label_radius if icon else (OUTER_RADIUS + INNER_RADIUS) / 2
            label_cx = CENTER_X + int(actual_label_radius * math.cos(angle_rad))
            label_cy = CENTER_Y - int(actual_label_radius * math.sin(angle_rad))

            bbox = self.draw.textbbox((0, 0), label, font=self.font_label)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]

            self.draw.text(
                (label_cx - text_width // 2, label_cy - text_height // 2),
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

    def update_metrics(self, metrics: dict):
        """Update stored metrics for dashboard display."""
        self.metrics = metrics

    def _render_dashboard(self) -> Image.Image:
        """Render metrics dashboard display."""
        # Create canvas
        self.canvas = Image.new('RGB', (self.width, self.height), BG_COLOR)
        self.draw = ImageDraw.Draw(self.canvas)

        # Draw outer ring decorations
        self.draw.ellipse(
            [10, 10, self.width - 10, self.height - 10],
            outline="#1a1a2e", width=2
        )

        # Title
        title = "SECUBOX"
        bbox = self.draw.textbbox((0, 0), title, font=self.font_title)
        self.draw.text(
            (CENTER_X - (bbox[2] - bbox[0]) // 2, 40),
            title, fill="#00d4ff", font=self.font_title
        )

        # Metrics in arc positions
        metrics_layout = [
            ("CPU", self.metrics.get("cpu_percent", 0), "%", "#C04E24", 150, 90),
            ("MEM", self.metrics.get("mem_percent", 0), "%", "#9A6010", 330, 90),
            ("DISK", self.metrics.get("disk_percent", 0), "%", "#803018", 150, 160),
            ("LOAD", self.metrics.get("load_avg_1", 0), "", "#3D35A0", 330, 160),
            ("TEMP", self.metrics.get("cpu_temp", 0), "°", "#0A5840", 150, 230),
            ("WIFI", self.metrics.get("wifi_rssi", -99), "dB", "#104A88", 330, 230),
        ]

        for label, value, unit, color, x, y in metrics_layout:
            # Draw metric box
            self.draw.rectangle([x - 60, y - 20, x + 60, y + 25], outline=color, width=2)
            # Label
            self.draw.text((x - 50, y - 15), label, fill=color, font=self.font_small)
            # Value
            val_str = f"{value:.1f}" if isinstance(value, float) else str(value)
            self.draw.text((x - 20, y), f"{val_str}{unit}", fill=TEXT_COLOR, font=self.font_title)

        # Center info
        hostname = self.metrics.get("hostname", "secubox")
        uptime = self.metrics.get("uptime_seconds", 0)
        uptime_str = f"up {uptime // 3600}h{(uptime % 3600) // 60:02d}"

        self.draw.ellipse(
            [CENTER_X - 60, CENTER_Y + 30, CENTER_X + 60, CENTER_Y + 110],
            fill=CENTER_COLOR, outline="#00d4ff", width=2
        )
        bbox = self.draw.textbbox((0, 0), hostname[:12], font=self.font_label)
        self.draw.text(
            (CENTER_X - (bbox[2] - bbox[0]) // 2, CENTER_Y + 50),
            hostname[:12], fill=TEXT_COLOR, font=self.font_label
        )
        bbox = self.draw.textbbox((0, 0), uptime_str, font=self.font_small)
        self.draw.text(
            (CENTER_X - (bbox[2] - bbox[0]) // 2, CENTER_Y + 75),
            uptime_str, fill="#6b6b7a", font=self.font_small
        )

        # Status bar
        status = "NOMINAL" if self.metrics.get("cpu_percent", 0) < 80 else "HIGH LOAD"
        status_color = HIGHLIGHT_COLOR if status == "NOMINAL" else "#e63946"
        self.draw.text((CENTER_X - 40, self.height - 50), f"● {status}",
                      fill=status_color, font=self.font_label)

        return self.canvas

    def _render_uboot(self) -> Image.Image:
        """Render U-Boot helper display for serial console."""
        self.canvas = Image.new('RGB', (self.width, self.height), BG_COLOR)
        self.draw = ImageDraw.Draw(self.canvas)

        # Border
        self.draw.ellipse([5, 5, self.width - 5, self.height - 5],
                         outline="#c9a84c", width=3)

        # Title
        title = "U-BOOT MODE"
        bbox = self.draw.textbbox((0, 0), title, font=self.font_title)
        self.draw.text((CENTER_X - (bbox[2] - bbox[0]) // 2, 30),
                      title, fill="#c9a84c", font=self.font_title)

        # Instructions - ESPRESSObin v7 correct commands
        instructions = [
            "Serial: 115200 8N1",
            "",
            "Boot from USB:",
            "  usb start",
            "  load usb 0:1 $loadaddr",
            "      boot/boot.scr",
            "  source $loadaddr",
            "",
            "Flash to eMMC:",
            "  usb start",
            "  load usb 0:1 $loadaddr",
            "      *.img.gz",
            "  gzwrite mmc 1",
            "      $loadaddr $filesize",
        ]

        y = 70
        for line in instructions:
            color = "#00d4ff" if line.endswith(":") else TEXT_COLOR
            if line.startswith("  "):
                color = HIGHLIGHT_COLOR
            self.draw.text((50, y), line, fill=color, font=self.font_small)
            y += 20

        # Status
        self.draw.text((CENTER_X - 60, self.height - 45),
                      "● AWAITING BOOT", fill="#c9a84c", font=self.font_label)

        return self.canvas

    def render(self, state: MenuState) -> Image.Image:
        """
        Render based on current mode.

        Args:
            state: Current menu state

        Returns:
            PIL Image (480x480)
        """
        # Handle different modes
        if state.mode == MenuMode.DASHBOARD:
            return self._render_dashboard()

        if state.mode == MenuMode.UBOOT:
            return self._render_uboot()

        # MENU mode (and others) - render radial menu
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
            icon_name = getattr(item, 'icon', None)
            self._draw_slice(i, item.label, icon_name, is_selected, is_enabled)

        # Draw center with menu ID as title
        menu_title = state.current_menu.name.replace('_', ' ')
        self._draw_center(menu_title)

        return self.canvas

    @staticmethod
    def hide_cursor():
        """Hide the TTY cursor to prevent blinking dot on display."""
        try:
            # Try to hide cursor on tty1
            with open('/dev/tty1', 'w') as tty:
                tty.write('\033[?25l')  # Hide cursor escape sequence
                tty.flush()
        except Exception as e:
            logger.debug(f"Could not hide cursor: {e}")

    def write_to_framebuffer(self, fb_path: str = "/dev/fb0"):
        """
        Write rendered image to framebuffer.

        Args:
            fb_path: Path to framebuffer device
        """
        if not self.canvas:
            logger.error("No canvas to write")
            return

        # Hide blinking cursor
        self.hide_cursor()

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
