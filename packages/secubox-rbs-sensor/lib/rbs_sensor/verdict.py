# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
OPAD verdict engine — scaffold.

Inputs: serving CellObservation + a window of NeighbourObservation feeds.
Output: one of {OK, SUSPECT, LIKELY_ROGUE} + the reasoning trace.

v0.1.0 ships the SHAPE only — the actual heuristics (RAT downgrade pressure,
PCID hopping, EARFCN/band mismatch with operator priors, TAC change without
mobility, asymmetric power profile, BCCH timing) land in v0.2 once we have
real data captures from a known-good modem.

Mitigations the verdict can trigger (executed by the actuator, not here):
  - lte-only  → AT+QCFG="nwscanmode",3,1     (refuse 2G)
  - rf-off    → AT+CFUN=4                    (RF detach)
  - restore   → restore saved nwscanmode + AT+CFUN=1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from rbs_sensor.observer import CellObservation, NeighbourObservation


class Verdict(str, Enum):
    OK = "ok"
    SUSPECT = "suspect"
    LIKELY_ROGUE = "likely_rogue"


@dataclass(frozen=True)
class VerdictReport:
    verdict: Verdict
    reasons: tuple[str, ...]
    serving_key: str
    sample_count: int

    @property
    def actionable(self) -> bool:
        """True if the verdict warrants automatic mitigation."""
        return self.verdict == Verdict.LIKELY_ROGUE


def orient(
    serving: CellObservation,
    neighbours: list[NeighbourObservation],
    history: list[CellObservation] | None = None,
) -> VerdictReport:
    """Produce a verdict from the current observation window.

    v0.1.0: stub returning OK. The real heuristic battery is in v0.2 —
    see docs/superpowers/specs/2026-05-20-secubox-wall-ep06.md §2 / §6.
    """
    return VerdictReport(
        verdict=Verdict.OK,
        reasons=("v0.1.0 scaffold: heuristics not yet implemented",),
        serving_key=serving.key,
        sample_count=len(neighbours),
    )
