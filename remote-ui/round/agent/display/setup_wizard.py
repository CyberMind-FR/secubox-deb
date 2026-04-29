#!/usr/bin/env python3
"""
SecuBox Eye Remote - Setup Wizard Display

Renders the setup wizard on the HyperPixel 2.1 Round display.
Handles 7-step wizard flow with touch interactions.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from __future__ import annotations

import math
import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any, Callable, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from ..api.setup import (
    get_setup_wizard,
    SetupWizard,
    SetupStep,
    SetupStatus,
    StepStatus,
    SecuBoxInfo,
)


# Display constants
DISPLAY_SIZE = 480
CENTER = DISPLAY_SIZE // 2

# Colors (SecuBox palette)
COLORS = {
    "background": "#0a0a0f",
    "gold": "#c9a84c",
    "green": "#00ff41",
    "red": "#e63946",
    "cyan": "#00d4ff",
    "purple": "#6e40c9",
    "white": "#e8e6d9",
    "muted": "#6b6b7a",
    "dark": "#1a1a1f",
}

# Step icons (emoji representations for text rendering)
STEP_ICONS = {
    SetupStep.WELCOME: "🔍",
    SetupStep.NETWORK: "🌐",
    SetupStep.SECURITY: "🔒",
    SetupStep.SERVICES: "⚙️",
    SetupStep.MESH: "🔗",
    SetupStep.VERIFY: "✓",
    SetupStep.COMPLETE: "🎉",
}


class TouchAction(Enum):
    """Touch actions in wizard."""
    NONE = "none"
    NEXT = "next"
    BACK = "back"
    SKIP = "skip"
    CANCEL = "cancel"
    SELECT = "select"


@dataclass
class TouchZone:
    """Defines a touch-sensitive zone."""
    x: int
    y: int
    width: int
    height: int
    action: TouchAction
    data: Optional[Any] = None

    def contains(self, tx: int, ty: int) -> bool:
        """Check if point is inside zone."""
        return (
            self.x <= tx <= self.x + self.width and
            self.y <= ty <= self.y + self.height
        )


class SetupWizardDisplay:
    """Renders setup wizard on display."""

    def __init__(self, wizard: Optional[SetupWizard] = None):
        self._wizard = wizard or get_setup_wizard()
        self._touch_zones: List[TouchZone] = []
        self._font_large: Optional[Any] = None
        self._font_medium: Optional[Any] = None
        self._font_small: Optional[Any] = None
        self._font_icon: Optional[Any] = None
        self._animation_frame = 0
        self._load_fonts()

    def _load_fonts(self):
        """Load fonts for rendering."""
        if not HAS_PIL:
            return

        try:
            self._font_large = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28
            )
            self._font_medium = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18
            )
            self._font_small = ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14
            )
            # For emoji/icons, use Noto if available
            try:
                self._font_icon = ImageFont.truetype(
                    "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf", 36
                )
            except Exception:
                self._font_icon = self._font_large
        except Exception:
            self._font_large = ImageFont.load_default()
            self._font_medium = ImageFont.load_default()
            self._font_small = ImageFont.load_default()
            self._font_icon = ImageFont.load_default()

    def _parse_color(self, color: str) -> Tuple[int, int, int]:
        """Parse hex color to RGB tuple."""
        if color.startswith("#"):
            color = color[1:]
        return (
            int(color[0:2], 16),
            int(color[2:4], 16),
            int(color[4:6], 16),
        )

    def _draw_circle_mask(self, draw: ImageDraw.ImageDraw):
        """Draw circular mask for round display."""
        # The round display is masked by hardware, but we add a subtle border
        draw.ellipse(
            [2, 2, DISPLAY_SIZE - 2, DISPLAY_SIZE - 2],
            outline=self._parse_color(COLORS["muted"]),
            width=2
        )

    def _draw_progress_ring(self, draw: ImageDraw.ImageDraw):
        """Draw progress ring around the edge."""
        wizard = self._wizard
        progress = wizard.get_progress()
        total_steps = progress["total_steps"]
        current_step = progress["current_step"]

        # Arc parameters
        radius = 230
        arc_width = 8

        for i in range(total_steps):
            # Calculate arc angles
            gap = 8  # degrees between arcs
            arc_span = (360 - (gap * total_steps)) / total_steps
            start_angle = i * (arc_span + gap) - 90  # Start from top
            end_angle = start_angle + arc_span

            # Determine color
            step_data = wizard.get_step_info(SetupStep(i))
            if step_data.status == StepStatus.COMPLETED:
                color = COLORS["green"]
            elif step_data.status == StepStatus.SKIPPED:
                color = COLORS["muted"]
            elif step_data.status == StepStatus.CURRENT:
                color = COLORS["gold"]
            elif step_data.status == StepStatus.FAILED:
                color = COLORS["red"]
            else:
                color = COLORS["dark"]

            # Draw arc
            bbox = [
                CENTER - radius, CENTER - radius,
                CENTER + radius, CENTER + radius
            ]
            draw.arc(bbox, start_angle, end_angle,
                     fill=self._parse_color(color), width=arc_width)

    def _draw_step_title(self, draw: ImageDraw.ImageDraw, step: SetupStep):
        """Draw the current step title."""
        step_data = self._wizard.get_step_info(step)

        # Step number
        step_num = f"Step {step.value + 1} of 7"
        if self._font_small:
            bbox = draw.textbbox((0, 0), step_num, font=self._font_small)
            text_width = bbox[2] - bbox[0]
            draw.text(
                (CENTER - text_width // 2, 60),
                step_num,
                fill=self._parse_color(COLORS["muted"]),
                font=self._font_small
            )

        # Title
        if self._font_large:
            bbox = draw.textbbox((0, 0), step_data.title, font=self._font_large)
            text_width = bbox[2] - bbox[0]
            draw.text(
                (CENTER - text_width // 2, 85),
                step_data.title,
                fill=self._parse_color(COLORS["gold"]),
                font=self._font_large
            )

        # Description
        if self._font_small:
            bbox = draw.textbbox((0, 0), step_data.description, font=self._font_small)
            text_width = bbox[2] - bbox[0]
            draw.text(
                (CENTER - text_width // 2, 120),
                step_data.description,
                fill=self._parse_color(COLORS["white"]),
                font=self._font_small
            )

    def _draw_navigation_buttons(self, draw: ImageDraw.ImageDraw):
        """Draw navigation buttons at bottom."""
        self._touch_zones = []  # Reset zones

        wizard = self._wizard
        current = wizard.current_step

        button_y = 400
        button_height = 40
        button_width = 100

        # Back button (left)
        if current.value > SetupStep.WELCOME.value:
            back_x = 60
            draw.rounded_rectangle(
                [back_x, button_y, back_x + button_width, button_y + button_height],
                radius=10,
                fill=self._parse_color(COLORS["dark"]),
                outline=self._parse_color(COLORS["muted"]),
            )
            if self._font_medium:
                draw.text(
                    (back_x + 25, button_y + 10),
                    "< Back",
                    fill=self._parse_color(COLORS["white"]),
                    font=self._font_medium
                )
            self._touch_zones.append(TouchZone(
                x=back_x, y=button_y,
                width=button_width, height=button_height,
                action=TouchAction.BACK
            ))

        # Next/Complete button (right)
        next_x = DISPLAY_SIZE - 60 - button_width
        if current == SetupStep.COMPLETE:
            button_text = "Done"
            button_color = COLORS["green"]
        else:
            button_text = "Next >"
            button_color = COLORS["gold"]

        draw.rounded_rectangle(
            [next_x, button_y, next_x + button_width, button_y + button_height],
            radius=10,
            fill=self._parse_color(button_color),
        )
        if self._font_medium:
            bbox = draw.textbbox((0, 0), button_text, font=self._font_medium)
            text_width = bbox[2] - bbox[0]
            draw.text(
                (next_x + (button_width - text_width) // 2, button_y + 10),
                button_text,
                fill=self._parse_color(COLORS["background"]),
                font=self._font_medium
            )
        self._touch_zones.append(TouchZone(
            x=next_x, y=button_y,
            width=button_width, height=button_height,
            action=TouchAction.NEXT
        ))

        # Skip button (center, for skippable steps)
        skippable = {SetupStep.SERVICES, SetupStep.MESH}
        if current in skippable:
            skip_x = CENTER - 40
            if self._font_small:
                draw.text(
                    (skip_x, button_y + 12),
                    "Skip",
                    fill=self._parse_color(COLORS["muted"]),
                    font=self._font_small
                )
            self._touch_zones.append(TouchZone(
                x=skip_x - 10, y=button_y,
                width=60, height=button_height,
                action=TouchAction.SKIP
            ))

    def _draw_welcome_content(self, draw: ImageDraw.ImageDraw):
        """Draw welcome step content."""
        info = self._wizard.state.secubox_info

        y = 160

        if info.detected:
            # SecuBox found
            draw.text(
                (CENTER - 80, y),
                "SecuBox Found!",
                fill=self._parse_color(COLORS["green"]),
                font=self._font_medium
            )
            y += 40

            # Connection indicator
            conn_icon = "🔌" if info.connection_type == "otg" else "📶"
            draw.text(
                (CENTER - 100, y),
                f"{conn_icon} {info.connection_type.upper()} @ {info.ip_address}",
                fill=self._parse_color(COLORS["white"]),
                font=self._font_small
            )
            y += 30

            # Model info
            draw.text(
                (CENTER - 80, y),
                f"Model: {info.model}",
                fill=self._parse_color(COLORS["white"]),
                font=self._font_small
            )
            y += 25

            # Version
            draw.text(
                (CENTER - 80, y),
                f"Version: {info.version}",
                fill=self._parse_color(COLORS["white"]),
                font=self._font_small
            )
            y += 25

            # Hostname
            draw.text(
                (CENTER - 80, y),
                f"Host: {info.hostname}",
                fill=self._parse_color(COLORS["white"]),
                font=self._font_small
            )

        else:
            # Searching animation
            dots = "." * (1 + (self._animation_frame % 3))
            draw.text(
                (CENTER - 100, y),
                f"Searching for SecuBox{dots}",
                fill=self._parse_color(COLORS["cyan"]),
                font=self._font_medium
            )
            y += 50

            draw.text(
                (CENTER - 120, y),
                "Connect via USB OTG or WiFi",
                fill=self._parse_color(COLORS["muted"]),
                font=self._font_small
            )

    def _draw_network_content(self, draw: ImageDraw.ImageDraw):
        """Draw network configuration content."""
        config = self._wizard.state.network_config
        y = 160

        # WAN section
        draw.text(
            (CENTER - 100, y),
            "WAN Interface",
            fill=self._parse_color(COLORS["gold"]),
            font=self._font_medium
        )
        y += 30

        mode = "DHCP" if config.wan_dhcp else "Static"
        draw.text(
            (CENTER - 80, y),
            f"Mode: {mode}",
            fill=self._parse_color(COLORS["white"]),
            font=self._font_small
        )
        y += 25

        draw.text(
            (CENTER - 80, y),
            f"Interface: {config.wan_interface}",
            fill=self._parse_color(COLORS["white"]),
            font=self._font_small
        )
        y += 40

        # LAN section
        draw.text(
            (CENTER - 100, y),
            "LAN Interface",
            fill=self._parse_color(COLORS["gold"]),
            font=self._font_medium
        )
        y += 30

        draw.text(
            (CENTER - 80, y),
            f"IP: {config.lan_ip}",
            fill=self._parse_color(COLORS["white"]),
            font=self._font_small
        )
        y += 25

        dhcp_status = "Enabled" if config.lan_dhcp_enabled else "Disabled"
        draw.text(
            (CENTER - 80, y),
            f"DHCP Server: {dhcp_status}",
            fill=self._parse_color(COLORS["white"]),
            font=self._font_small
        )

    def _draw_security_content(self, draw: ImageDraw.ImageDraw):
        """Draw security configuration content."""
        config = self._wizard.state.security_config
        y = 160

        # Admin password status
        pwd_status = "✓ Set" if config.admin_password_set else "○ Not set"
        pwd_color = COLORS["green"] if config.admin_password_set else COLORS["red"]
        draw.text(
            (CENTER - 100, y),
            f"Admin Password: {pwd_status}",
            fill=self._parse_color(pwd_color),
            font=self._font_medium
        )
        y += 40

        # TLS certificate status
        tls_status = "✓ Generated" if config.tls_cert_generated else "○ Pending"
        tls_color = COLORS["green"] if config.tls_cert_generated else COLORS["muted"]
        draw.text(
            (CENTER - 100, y),
            f"TLS Certificate: {tls_status}",
            fill=self._parse_color(tls_color),
            font=self._font_medium
        )
        y += 40

        # SSH key status
        ssh_status = "✓ Installed" if config.ssh_key_installed else "○ Optional"
        ssh_color = COLORS["green"] if config.ssh_key_installed else COLORS["muted"]
        draw.text(
            (CENTER - 100, y),
            f"SSH Key: {ssh_status}",
            fill=self._parse_color(ssh_color),
            font=self._font_medium
        )

    def _draw_services_content(self, draw: ImageDraw.ImageDraw):
        """Draw services configuration content."""
        config = self._wizard.state.services_config
        y = 160

        services = [
            ("CrowdSec IDS", config.crowdsec_enabled),
            ("WireGuard VPN", config.wireguard_enabled),
            ("Firewall", config.firewall_enabled),
            ("DPI Analysis", config.dpi_enabled),
            ("DNS Filtering", config.dns_filtering_enabled),
        ]

        for name, enabled in services:
            status = "✓" if enabled else "○"
            color = COLORS["green"] if enabled else COLORS["muted"]
            draw.text(
                (CENTER - 100, y),
                f"{status} {name}",
                fill=self._parse_color(color),
                font=self._font_medium
            )
            y += 35

    def _draw_mesh_content(self, draw: ImageDraw.ImageDraw):
        """Draw mesh configuration content."""
        config = self._wizard.state.mesh_config
        y = 160

        # Mode selection
        draw.text(
            (CENTER - 80, y),
            "Network Mode",
            fill=self._parse_color(COLORS["gold"]),
            font=self._font_medium
        )
        y += 40

        modes = [
            ("Standalone", "standalone"),
            ("Join MirrorNet", "join"),
            ("Create Mesh", "create"),
        ]

        for name, mode in modes:
            is_selected = config.mode == mode
            color = COLORS["cyan"] if is_selected else COLORS["muted"]
            prefix = "●" if is_selected else "○"
            draw.text(
                (CENTER - 80, y),
                f"{prefix} {name}",
                fill=self._parse_color(color),
                font=self._font_medium
            )
            y += 35

    def _draw_verify_content(self, draw: ImageDraw.ImageDraw):
        """Draw verification results content."""
        step_data = self._wizard.get_step_info(SetupStep.VERIFY)
        results = step_data.data

        y = 160

        if not results:
            # Running verification
            dots = "." * (1 + (self._animation_frame % 3))
            draw.text(
                (CENTER - 100, y),
                f"Verifying configuration{dots}",
                fill=self._parse_color(COLORS["cyan"]),
                font=self._font_medium
            )
            return

        # API connectivity
        api_ok = results.get("api", False)
        api_color = COLORS["green"] if api_ok else COLORS["red"]
        api_status = "✓" if api_ok else "✗"
        draw.text(
            (CENTER - 100, y),
            f"{api_status} API Connectivity",
            fill=self._parse_color(api_color),
            font=self._font_medium
        )
        y += 35

        # Network
        net_ok = results.get("network", False)
        net_color = COLORS["green"] if net_ok else COLORS["red"]
        net_status = "✓" if net_ok else "✗"
        draw.text(
            (CENTER - 100, y),
            f"{net_status} Network",
            fill=self._parse_color(net_color),
            font=self._font_medium
        )
        y += 35

        # Services
        services = results.get("services", {})
        for name, ok in services.items():
            svc_color = COLORS["green"] if ok else COLORS["muted"]
            svc_status = "✓" if ok else "○"
            draw.text(
                (CENTER - 100, y),
                f"{svc_status} {name.title()}",
                fill=self._parse_color(svc_color),
                font=self._font_small
            )
            y += 25

    def _draw_complete_content(self, draw: ImageDraw.ImageDraw):
        """Draw completion content."""
        y = 160

        # Checkmark animation
        draw.text(
            (CENTER - 20, y),
            "✓",
            fill=self._parse_color(COLORS["green"]),
            font=self._font_large
        )
        y += 50

        draw.text(
            (CENTER - 80, y),
            "Setup Complete!",
            fill=self._parse_color(COLORS["gold"]),
            font=self._font_large
        )
        y += 45

        draw.text(
            (CENTER - 120, y),
            "Your SecuBox is ready to use.",
            fill=self._parse_color(COLORS["white"]),
            font=self._font_small
        )
        y += 35

        draw.text(
            (CENTER - 100, y),
            "Tap Done to finish setup.",
            fill=self._parse_color(COLORS["muted"]),
            font=self._font_small
        )

    def render(self) -> Optional[Image.Image]:
        """Render the current wizard state."""
        if not HAS_PIL:
            return None

        # Create image
        img = Image.new("RGB", (DISPLAY_SIZE, DISPLAY_SIZE),
                        self._parse_color(COLORS["background"]))
        draw = ImageDraw.Draw(img)

        # Draw components
        self._draw_circle_mask(draw)
        self._draw_progress_ring(draw)

        current_step = self._wizard.current_step
        self._draw_step_title(draw, current_step)

        # Draw step-specific content
        content_renderers = {
            SetupStep.WELCOME: self._draw_welcome_content,
            SetupStep.NETWORK: self._draw_network_content,
            SetupStep.SECURITY: self._draw_security_content,
            SetupStep.SERVICES: self._draw_services_content,
            SetupStep.MESH: self._draw_mesh_content,
            SetupStep.VERIFY: self._draw_verify_content,
            SetupStep.COMPLETE: self._draw_complete_content,
        }

        renderer = content_renderers.get(current_step)
        if renderer:
            renderer(draw)

        self._draw_navigation_buttons(draw)

        # Increment animation frame
        self._animation_frame += 1

        return img

    def handle_touch(self, x: int, y: int) -> TouchAction:
        """Handle touch event and return action."""
        for zone in self._touch_zones:
            if zone.contains(x, y):
                return zone.action
        return TouchAction.NONE

    async def process_action(self, action: TouchAction) -> bool:
        """Process a touch action."""
        wizard = self._wizard

        if action == TouchAction.NEXT:
            if wizard.current_step == SetupStep.COMPLETE:
                await wizard.complete_setup()
            else:
                await wizard.next_step()
            return True

        elif action == TouchAction.BACK:
            await wizard.previous_step()
            return True

        elif action == TouchAction.SKIP:
            await wizard.skip_step()
            return True

        elif action == TouchAction.CANCEL:
            await wizard.cancel_setup()
            return True

        return False


# Singleton instance
_wizard_display: Optional[SetupWizardDisplay] = None


def get_wizard_display() -> SetupWizardDisplay:
    """Get singleton wizard display instance."""
    global _wizard_display
    if _wizard_display is None:
        _wizard_display = SetupWizardDisplay()
    return _wizard_display
