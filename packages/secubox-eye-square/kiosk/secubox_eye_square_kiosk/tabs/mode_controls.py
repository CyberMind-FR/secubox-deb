# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/mode_controls.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Mode Controls tab — USB gadget mode + service restart + lockdown + transport."""
from __future__ import annotations

import logging
from typing import Optional

from PIL import Image, ImageDraw

from .. import theme

log = logging.getLogger("secubox_eye_square_kiosk.tabs.mode_controls")

USB_BUTTONS = ["normal", "flash", "debug", "tty", "auth", "stop"]
SERVICE_BUTTONS = [
    ("secubox-hub", "RESTART HUB"),
    ("secubox-auth", "RESTART AUTH"),
    ("restart-all", "RESTART ALL"),
    ("lockdown", "LOCKDOWN !"),
]
DESTRUCTIVE = {"flash", "stop", "restart-all", "lockdown"}

USB_ROW_Y = 40
SERVICE_ROW_Y = 200
TRANSPORT_ROW_Y = 360
CELL_W = 100
CELL_H = 64


class ModeControlsTab:
    """Touch-button grid. Destructive actions require confirm tap."""

    def __init__(self, helper_client):
        self.helper = helper_client
        self.transport_active = "SIM"
        self.pending_confirm: Optional[str] = None

    def update_transport(self, active: str) -> None:
        self.transport_active = active

    def handle_tap(self, x: int, y: int) -> None:
        """Map (x, y) to a button. Destructive actions stage pending_confirm; second tap commits."""
        # USB mode buttons — top 2x3 grid
        if USB_ROW_Y <= y < USB_ROW_Y + 2 * CELL_H:
            row = (y - USB_ROW_Y) // CELL_H
            col = x // CELL_W
            idx = row * 3 + col
            if 0 <= idx < len(USB_BUTTONS):
                mode = USB_BUTTONS[idx]
                self._invoke_or_stage(mode, lambda: self.helper.set_usb_mode(mode))
                return
        # Service buttons — middle 2x2 grid
        if SERVICE_ROW_Y <= y < SERVICE_ROW_Y + 2 * CELL_H:
            row = (y - SERVICE_ROW_Y) // CELL_H
            col = x // (320 // 2)
            idx = row * 2 + col
            if 0 <= idx < len(SERVICE_BUTTONS):
                action, _label = SERVICE_BUTTONS[idx]
                self._invoke_or_stage(action, lambda: self._service_action(action))
                return

    def _invoke_or_stage(self, action: str, callback) -> None:
        if action in DESTRUCTIVE and self.pending_confirm != action:
            self.pending_confirm = action
            return
        self.pending_confirm = None
        try:
            callback()
        except Exception as e:
            log.warning("action %s failed: %s", action, e)

    def confirm_pending(self) -> None:
        """Called externally after the user confirms via the confirm overlay tap."""
        if self.pending_confirm is None:
            return
        action = self.pending_confirm
        self.pending_confirm = None
        try:
            if action in USB_BUTTONS:
                self.helper.set_usb_mode(action)
            else:
                self._service_action(action)
        except Exception as e:
            log.warning("confirm action %s failed: %s", action, e)

    def _service_action(self, action: str) -> None:
        if action == "lockdown":
            self.helper.lockdown()
        elif action == "restart-all":
            for unit in ("secubox-hub", "secubox-auth", "secubox-system"):
                self.helper.restart_service(unit)
        else:
            self.helper.restart_service(action)

    def draw(self, region: Image.Image) -> None:
        draw = ImageDraw.Draw(region)
        w, _ = region.size
        # USB buttons header
        draw.text((10, 16), "USB GADGET MODE", fill=theme.GOLD_HERMETIC)
        for i, mode in enumerate(USB_BUTTONS):
            row = i // 3
            col = i % 3
            x = col * CELL_W + 10
            y = USB_ROW_Y + row * CELL_H
            colour = theme.CINNABAR if mode in DESTRUCTIVE else theme.TEXT_PRIMARY
            draw.rectangle((x, y, x + CELL_W - 5, y + CELL_H - 5),
                           outline=colour, width=1)
            draw.text((x + 8, y + 24), mode.upper(), fill=colour)
        # Service buttons
        draw.text((10, SERVICE_ROW_Y - 24), "SECUBOX SERVICE",
                  fill=theme.GOLD_HERMETIC)
        for i, (_, label) in enumerate(SERVICE_BUTTONS):
            row = i // 2
            col = i % 2
            x = col * (w // 2) + 10
            y = SERVICE_ROW_Y + row * CELL_H
            colour = theme.CINNABAR if SERVICE_BUTTONS[i][0] in DESTRUCTIVE else theme.TEXT_PRIMARY
            draw.rectangle((x, y, x + w // 2 - 15, y + CELL_H - 5),
                           outline=colour, width=1)
            draw.text((x + 8, y + 24), label, fill=colour)
        # Transport
        draw.text((10, TRANSPORT_ROW_Y - 24), "TRANSPORT",
                  fill=theme.GOLD_HERMETIC)
        dot = "●" if self.transport_active in ("OTG", "WiFi") else "○"
        draw.text((10, TRANSPORT_ROW_Y), f"{dot} {self.transport_active}",
                  fill=theme.MATRIX_GREEN if dot == "●" else theme.TEXT_MUTED)
        # Confirm overlay
        if self.pending_confirm:
            draw.rectangle((10, 100, w - 10, 200), fill=theme.COSMOS_BLACK,
                           outline=theme.CINNABAR, width=2)
            draw.text((20, 120), f"Confirm {self.pending_confirm}?",
                      fill=theme.CINNABAR)
            draw.text((20, 150), "Tap again to confirm",
                      fill=theme.TEXT_MUTED)
