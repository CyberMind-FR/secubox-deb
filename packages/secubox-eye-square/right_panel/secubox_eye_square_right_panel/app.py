# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox Eye Square — right panel QMainWindow (320x480 at +480+0)."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget

from .helper_client import HelperClient
from .ipc_bridge import IPCBridge
from .tabs.alerts import AlertsTab, AlertItem
from .tabs.console import ConsoleTab
from .tabs.mode_controls import ModeControlsTab
from .tabs.module_detail import ModuleDetailTab
from .theme import parse_palette

log = logging.getLogger("eye_square_right_panel")

HELPER_SOCK = "/run/secubox/eye-square-helper.sock"
PALETTE_PATH = Path("/var/www/common/css/palette.css")
WINDOW_W = 320
WINDOW_H = 480
WINDOW_X = 480
WINDOW_Y = 0


class RightPanelWindow(QMainWindow):
    """QMainWindow housing the 4 tabs. Pinned by Openbox to (480,0,320,480)."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecuBox Eye Square")
        # Frameless so Openbox rc.xml geometry pins work cleanly.
        self.setWindowFlag(Qt.FramelessWindowHint, True)
        self.setGeometry(WINDOW_X, WINDOW_Y, WINDOW_W, WINDOW_H)

        self.palette_vars = parse_palette(PALETTE_PATH)
        self.helper = HelperClient(HELPER_SOCK)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.alerts_tab = AlertsTab(on_row_tapped=self._on_alert_tapped)
        self.module_tab = ModuleDetailTab()
        self.console_tab = ConsoleTab()
        self.mode_tab = ModeControlsTab(self.helper)
        self.tabs.addTab(self.alerts_tab, "ALERTS")
        self.tabs.addTab(self.module_tab, "DETAIL")
        self.tabs.addTab(self.console_tab, "CON")
        self.tabs.addTab(self.mode_tab, "CTL")
        self.setCentralWidget(self.tabs)

        self.bridge = IPCBridge()
        self.bridge.on_module_tap = self._on_module_tap_event
        self.bridge.on_transport_change = self._on_transport_change_event

    def _on_alert_tapped(self, item: AlertItem):
        """Clicking an alert row routes to the Module Detail tab."""
        self.tabs.setCurrentWidget(self.module_tab)
        self.module_tab.load_module(item.module, "", value=0.0, history=[])

    def _on_module_tap_event(self, module: str):
        """Chromium TM signaled a pod tap → switch to Module Detail."""
        self.tabs.setCurrentWidget(self.module_tab)
        self.module_tab.load_module(module, "", value=0.0, history=[])

    def _on_transport_change_event(self, active: str):
        """Chromium TM signaled a transport transition → update Mode tab."""
        self.mode_tab.update_transport(active)


async def amain():
    """Entry coroutine. Builds the window, starts the IPC bridge."""
    win = RightPanelWindow()
    win.show()
    asyncio.create_task(win.bridge.serve())
    # Keep the coroutine alive; qasync drives Qt + asyncio together.
    while True:
        await asyncio.sleep(3600)


def main():
    """Synchronous entry point. Creates QApplication + qasync event loop."""
    import qasync
    app = QApplication([])
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    with loop:
        loop.run_until_complete(amain())


if __name__ == "__main__":
    main()
