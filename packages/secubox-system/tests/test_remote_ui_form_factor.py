# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: tests/test_remote_ui_form_factor
Tests for the form_factor field on RemoteUIConnectedRequest (ref #127).
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the secubox-system package importable from this test file
_PKG = Path(__file__).resolve().parent.parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from models.system import RemoteUIConnectedRequest, TransportType


def test_form_factor_defaults_to_round_for_backcompat():
    """Older udev rules that don't send form_factor must keep working."""
    req = RemoteUIConnectedRequest(
        transport=TransportType.OTG,
        peer="10.55.0.2",
    )
    assert req.form_factor == "round"


def test_form_factor_accepts_round_explicit():
    req = RemoteUIConnectedRequest(
        transport=TransportType.OTG,
        peer="10.55.0.2",
        form_factor="round",
    )
    assert req.form_factor == "round"


def test_form_factor_accepts_square():
    req = RemoteUIConnectedRequest(
        transport=TransportType.OTG,
        peer="10.55.0.2",
        form_factor="square",
    )
    assert req.form_factor == "square"


def test_form_factor_rejects_unknown_value():
    """Pydantic Literal must reject non-{round,square} values."""
    with pytest.raises(Exception):
        # ValidationError or ValueError depending on Pydantic v1/v2
        RemoteUIConnectedRequest(
            transport=TransportType.OTG,
            peer="10.55.0.2",
            form_factor="oval",
        )
