# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-sentinelle-gsm — passive GSM rogue-BTS sensor (MIND).

This sensor is OFF-PATH by construction (RX-only via SDR). It NEVER emits
RF and NEVER captures third-party correspondence. Subscriber identifiers
(IMSI/IMEI/TMSI) are HMAC-truncated by default (PROD mode); plaintext
observation only allowed in LAB mode after explicit consent banner +
audit-log entry.

See docs/superpowers/specs/2026-05-20-secubox-sentinelle-gsm.md §2 + §6
for the doctrinal contract.
"""

from sentinelle_gsm.observer import (
    CAPTURES_PLAINTEXT_IMSI,
    Anonymizer,
    GsmCellObservation,
    Mode,
)

__all__ = [
    "CAPTURES_PLAINTEXT_IMSI",
    "Anonymizer",
    "GsmCellObservation",
    "Mode",
]
__version__ = "0.1.0"
