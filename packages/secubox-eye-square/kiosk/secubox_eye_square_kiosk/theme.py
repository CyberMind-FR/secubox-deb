# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Backward-compat shim — re-exports secubox_common.theme.

Square/ kiosk modules and tests historically import from
secubox_eye_square_kiosk.theme. This shim keeps those imports working
while the canonical palette + DEFAULT_FONT live in secubox_common.theme.
"""
from secubox_common.theme import *  # noqa: F401,F403
from secubox_common.theme import (  # noqa: F401
    AUTH, WALL, BOOT, MIND, ROOT, MESH,
    COSMOS_BLACK, GOLD_HERMETIC, CINNABAR, MATRIX_GREEN,
    CYBER_CYAN, VOID_PURPLE, TEXT_PRIMARY, TEXT_MUTED,
    SEVERITY, load_default_font,
)

# Older callers expected a module-level constant DEFAULT_FONT.
DEFAULT_FONT = load_default_font(12)
