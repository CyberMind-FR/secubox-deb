# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Shared pytest fixtures for secubox_common."""
import pytest
from PIL import Image


@pytest.fixture
def blank_round() -> Image.Image:
    """480×480 RGBA black canvas — round form factor."""
    return Image.new("RGBA", (480, 480), (0, 0, 0, 255))


@pytest.fixture
def blank_square() -> Image.Image:
    """800×480 RGBA black canvas — square form factor."""
    return Image.new("RGBA", (800, 480), (0, 0, 0, 255))
