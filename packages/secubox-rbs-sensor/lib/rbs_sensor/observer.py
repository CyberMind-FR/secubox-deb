# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
OPAD framework: Observer protocol + CellObservation/NeighbourObservation
dataclasses.

Hard invariant (structural proof — see tests/test_opad_invariant.py):
  CellObservation and NeighbourObservation have NO field that could carry
  an IMSI, TMSI, IMEI, MSISDN, ICCID, or any other subscriber-bound id.

  The fields below describe ONLY the broadcast cell identity (which is
  public) and own-modem RX measurements. None of these reveal who the
  third-party subscribers are.

The module-level constant CAPTURES_SUBSCRIBER_IDENTIFIERS is exposed via
the FastAPI /status endpoint so an auditor can prove the invariant without
inspecting source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

CAPTURES_SUBSCRIBER_IDENTIFIERS: bool = False


@dataclass(frozen=True)
class CellObservation:
    """A single observation of a serving cell.

    All fields are PUBLIC cell-broadcast identifiers or own-modem RX
    measurements. No subscriber-bound data lives here.
    """

    rat: str           # "LTE" | "GSM" | "WCDMA"
    mcc: int           # Mobile Country Code (broadcast)
    mnc: int           # Mobile Network Code (broadcast)
    cid: int           # Cell ID (broadcast hex → int)
    area_code: int     # TAC (LTE) or LAC (GSM/WCDMA) — broadcast hex → int
    arfcn: int         # EARFCN (LTE) / ARFCN (GSM) / UARFCN (WCDMA)
    rx_power_dbm: float  # RSRP (LTE) / RXlev (GSM) — own-modem measurement
    captured_at: float   # POSIX timestamp, time.time()

    # Optional measurements; absent fields are None, never sentinel placeholders.
    pcid: Optional[int] = None         # LTE physical cell ID (broadcast)
    bsic: Optional[int] = None         # GSM BSIC (broadcast)
    rsrq_db: Optional[float] = None    # LTE only
    sinr_db: Optional[float] = None    # LTE only
    band: Optional[int] = None         # Carrier band number

    @property
    def key(self) -> str:
        """Stable identity for dedupe in the observer feed."""
        return f"{self.rat}:{self.mcc}-{self.mnc}:{self.area_code}:{self.cid}"


@dataclass(frozen=True)
class NeighbourObservation:
    """A neighbour-cell measurement.

    Neighbours expose only RAT + carrier + PCID/BSIC + RX measurements —
    NOT the full mcc/mnc/cid. Heuristics that consume these (RAT downgrade
    pressure, unexpected RAT presence) operate on this PARTIAL view.

    Per spec §4.2: never synthesize a CellObservation.key from a neighbour.
    """

    rat: str
    arfcn: int
    rx_power_dbm: float
    captured_at: float

    pcid: Optional[int] = None
    bsic: Optional[int] = None
    rsrq_db: Optional[float] = None
    sinr_db: Optional[float] = None


@runtime_checkable
class Observer(Protocol):
    """A backend that produces serving cell + neighbour observations.

    Implementations: Ep06Observer (this package), future Sierra/Quectel/SDR
    backends drop in via this Protocol.
    """

    @property
    def name(self) -> str:
        """Short identifier for the observer backend (e.g. 'ep06')."""
        ...

    @property
    def captures_subscriber_identifiers(self) -> bool:
        """MUST return False for any OPAD-compliant observer."""
        ...

    def serving_cell(self) -> Optional[CellObservation]:
        """Latest serving-cell observation; None if no camp."""
        ...

    def neighbours(self) -> list[NeighbourObservation]:
        """Latest neighbour measurements (possibly empty)."""
        ...

    def is_present(self) -> bool:
        """True if the underlying hardware is detected and the AT port is
        responsive. Sensors that are not present return False for everything."""
        ...
