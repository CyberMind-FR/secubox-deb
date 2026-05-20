# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Privacy framework: Anonymizer (HMAC) + GsmCellObservation dataclass + Mode.

Hard invariant (structural proof — see tests/test_privacy_invariant.py):
  GsmCellObservation has NO field that could carry a plaintext IMSI/TMSI/
  IMEI/MSISDN/ICCID. Subscriber identifiers, when present in PROD mode,
  are stored only as HMAC-SHA256-truncated tokens via Anonymizer.

The module-level constant CAPTURES_PLAINTEXT_IMSI is exposed via the
FastAPI /status endpoint so an auditor can prove the invariant.

LAB mode is supported but gated: it requires (1) an explicit operator
flip via POST /mode, (2) a consent banner acknowledgement, (3) an audit
log entry. LAB mode is intended ONLY for owned SIMs / consented devices.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


CAPTURES_PLAINTEXT_IMSI: bool = False


class Mode(str, Enum):
    """Operating mode — PROD anonymizes, LAB keeps plaintext.

    PROD is the default. Flipping to LAB requires an explicit POST /mode
    call AND a consent banner ack — see api/main.py.
    """

    PROD = "prod"
    LAB = "lab"


# Anonymized identifiers are truncated to this many hex chars (16 = 64 bits).
# Enough for dedupe/counting, NOT enough for reverse identification.
ANON_TRUNCATE_HEX = 16


@dataclass
class Anonymizer:
    """HMAC-SHA256 truncated anonymizer.

    The key is generated at install time (see lib/sentinelle_gsm/install.py
    or the deb postinst) into /etc/secubox/secrets/sentinelle-gsm-hmac with
    mode 0600 root:secubox. It is NEVER exported, NEVER rotated mid-run
    (rotation invalidates all dedupe counters — must be a deliberate op).

    For LAB mode: pass identifier through .lab_passthrough() instead of
    .anonymize() — that method is a NOOP and is explicitly named to make
    code review trivially auditable.
    """

    key: bytes
    mode: Mode = Mode.PROD

    @classmethod
    def from_file(cls, path: Path, mode: Mode = Mode.PROD) -> "Anonymizer":
        key = path.read_bytes()
        if len(key) < 32:
            raise ValueError(
                f"HMAC key at {path} is {len(key)} bytes; need >= 32."
            )
        return cls(key=key, mode=mode)

    @classmethod
    def ephemeral(cls, mode: Mode = Mode.PROD) -> "Anonymizer":
        """For tests only. Generates a key in memory; never persisted."""
        return cls(key=secrets.token_bytes(32), mode=mode)

    def anonymize(self, identifier: str) -> str:
        """HMAC-SHA256, hex-truncated. Always used in PROD."""
        if not identifier:
            return ""
        mac = hmac.new(self.key, identifier.encode(), hashlib.sha256)
        return mac.hexdigest()[:ANON_TRUNCATE_HEX]

    def lab_passthrough(self, identifier: str) -> str:
        """Plaintext passthrough for LAB mode only. Raises in PROD.

        The two-method API (anonymize / lab_passthrough) is deliberate:
        code review immediately spots any call to lab_passthrough in a
        non-LAB code path. A single .observe(id) method that branches
        internally would be much harder to audit.
        """
        if self.mode is not Mode.LAB:
            raise RuntimeError(
                "lab_passthrough called outside LAB mode — refusing"
            )
        return identifier


@dataclass(frozen=True)
class GsmCellObservation:
    """A single GSM serving-cell observation.

    All fields are PUBLIC cell-broadcast identifiers or own-radio RX
    measurements. NO subscriber-bound data.

    The 8 spec §6.1 heuristics consume these and produce a score 0–100 +
    reasons[] list (see lib/sentinelle_gsm/scoring.py).
    """

    arfcn: int                # Carrier (broadcast)
    cid: int                  # Cell ID (broadcast)
    lac: int                  # Location Area Code (broadcast)
    mcc: int                  # Mobile Country Code (broadcast)
    mnc: int                  # Mobile Network Code (broadcast)
    rx_power_dbm: float       # Own-radio RX measurement
    captured_at: float        # POSIX timestamp

    # GSM-specific signals consumed by the scoring heuristics
    ciphers_offered: tuple[str, ...] = field(default_factory=tuple)  # ("A5/0",...)
    t3212_minutes: Optional[int] = None      # periodic update timer
    neighbours_arfcns: tuple[int, ...] = field(default_factory=tuple)
    identity_request_count: int = 0          # incremented on each Identity Request
    location_update_count: int = 0           # incremented on each Loc Update

    @property
    def key(self) -> str:
        return f"GSM:{self.mcc}-{self.mnc}:{self.lac}:{self.cid}:{self.arfcn}"
