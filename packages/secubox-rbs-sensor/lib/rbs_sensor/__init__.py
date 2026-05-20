# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-rbs-sensor — Rogue Base Station sensor (WALL layer).

OPAD doctrine (Off-Path Active Defense) — the sensor reports what the modem
HEARS (cell broadcasts) and what its OWN session looks like; it never captures
subscriber identifiers from third parties.

Structural proof of the invariant: CellObservation / NeighbourObservation
have NO fields that could carry IMSI/TMSI. See tests/test_opad_invariant.py.
"""

from rbs_sensor.observer import (
    CAPTURES_SUBSCRIBER_IDENTIFIERS,
    CellObservation,
    NeighbourObservation,
    Observer,
)

__all__ = [
    "CAPTURES_SUBSCRIBER_IDENTIFIERS",
    "CellObservation",
    "NeighbourObservation",
    "Observer",
]
__version__ = "0.1.0"
