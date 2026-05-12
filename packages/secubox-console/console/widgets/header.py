# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Console TUI — Board Header Widget
"""
from __future__ import annotations
from textual.widgets import Static
from textual.app import ComposeResult

from ..theme import get_board_name, get_board_badge


class BoardHeader(Static):
    """Header widget showing board name and badge."""

    def compose(self) -> ComposeResult:
        name = get_board_name()
        badge = get_board_badge()

        if badge:
            yield Static(f"{name} [{badge}]", classes="board-header")
        else:
            yield Static(name, classes="board-header")
