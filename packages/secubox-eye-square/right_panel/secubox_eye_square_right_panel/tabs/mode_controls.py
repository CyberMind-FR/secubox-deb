# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Mode Controls tab — USB gadget mode + service restart + lockdown + transport indicator."""
from __future__ import annotations

import asyncio
import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout, QGroupBox, QHBoxLayout, QLabel, QMessageBox,
    QPushButton, QVBoxLayout, QWidget,
)

log = logging.getLogger("eye_square_right_panel.mode_controls")

_DESTRUCTIVE = frozenset({"flash", "stop", "restart-all", "lockdown"})


class ModeControlsTab(QWidget):
    """Tab 4: USB mode, service restart, lockdown, transport indicator."""

    def __init__(self, helper_client, parent=None):
        super().__init__(parent)
        self.helper = helper_client

        # USB gadget mode group
        usb_box = QGroupBox("USB GADGET MODE")
        usb_grid = QGridLayout(usb_box)
        self.usb_buttons: dict[str, QPushButton] = {}
        modes = [("normal", 0, 0), ("flash", 0, 1), ("debug", 0, 2),
                 ("tty", 1, 0), ("auth", 1, 1), ("stop", 1, 2)]
        for mode, row, col in modes:
            btn = QPushButton(mode.upper())
            btn.setMinimumHeight(48)
            btn.clicked.connect(lambda _checked=False, m=mode: self._on_usb_mode(m))
            usb_grid.addWidget(btn, row, col)
            self.usb_buttons[mode] = btn

        # Service restart group
        svc_box = QGroupBox("SECUBOX SERVICE")
        svc_grid = QGridLayout(svc_box)
        self.service_buttons: dict[str, QPushButton] = {}
        services = [
            ("secubox-hub", 0, 0, "RESTART HUB"),
            ("secubox-auth", 0, 1, "RESTART AUTH"),
            ("restart-all", 1, 0, "RESTART ALL"),
            ("lockdown", 1, 1, "LOCKDOWN !"),
        ]
        for action, row, col, label in services:
            btn = QPushButton(label)
            btn.setMinimumHeight(48)
            btn.clicked.connect(lambda _checked=False, a=action: self._on_service(a))
            svc_grid.addWidget(btn, row, col)
            self.service_buttons[action] = btn

        # Transport indicator
        tport_box = QGroupBox("TRANSPORT")
        tport_h = QHBoxLayout(tport_box)
        self.transport_label = QLabel("○ SIM")
        self.transport_label.setAlignment(Qt.AlignCenter)
        tport_h.addWidget(self.transport_label)

        layout = QVBoxLayout(self)
        layout.addWidget(usb_box)
        layout.addWidget(svc_box)
        layout.addWidget(tport_box)
        layout.addStretch()

    def update_transport(self, active: str):
        dot = "●" if active in ("OTG", "WiFi") else "○"
        self.transport_label.setText(f"{dot} {active}")

    def _needs_confirm(self, action: str) -> bool:
        return action in _DESTRUCTIVE

    def _confirm(self, title: str, text: str) -> bool:
        reply = QMessageBox.question(
            self, title, text,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return reply == QMessageBox.Yes

    def _on_usb_mode(self, mode: str):
        if self._needs_confirm(mode):
            if not self._confirm("Confirm USB mode", f"Switch USB gadget to {mode.upper()}?"):
                return
        asyncio.ensure_future(self._async_set_mode(mode))

    async def _async_set_mode(self, mode: str):
        try:
            await self.helper.set_usb_mode(mode)
        except Exception as e:
            log.warning("set_usb_mode failed: %s", e)

    def _on_service(self, action: str):
        if self._needs_confirm(action):
            if not self._confirm("Confirm service action", f"Run {action}?"):
                return
        asyncio.ensure_future(self._async_service(action))

    async def _async_service(self, action: str):
        try:
            if action == "lockdown":
                await self.helper.lockdown()
            elif action == "restart-all":
                # restart-all could call multiple — for now restart hub as a placeholder
                # Phase 2 follow-up: implement restart-all properly via systemctl
                for unit in ("secubox-hub", "secubox-auth", "secubox-system"):
                    await self.helper.restart_service(unit)
            else:
                await self.helper.restart_service(action)
        except Exception as e:
            log.warning("service action %s failed: %s", action, e)
