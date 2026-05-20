# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
8-heuristic scoring engine — scaffold.

Each rule returns (score_contribution, reason_str) or (0, None).
The final cell score is sum-clamped to [0, 100]. >= threshold → alert.

v0.1.0 ships the SHAPE only; v0.2 plugs the actual baseline + thresholds
once we have real GSMTAP captures.

Heuristics, per spec §6.1:
  1. Cipher downgrade (A5/0 advertised or A5/1 where carrier uses A5/3)
  2. Ghost BTS (CID/LAC not in baseline, anomalous power)
  3. Identity mismatch (MCC/MNC inconsistent with carrier-on-ARFCN)
  4. Relocalization storm (frequent LAC churn)
  5. Identity Request abuse (repeated IMSI requests — IMSI-catcher signature)
  6. Anomalous neighbours (empty/incoherent neighbour list, aberrant C1/C2)
  7. T3212 out of carrier band
  8. Orphan ARFCN (carrier outside the carrier's known frequency plan)
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinelle_gsm.observer import GsmCellObservation


@dataclass(frozen=True)
class CellScore:
    cell_key: str
    score: int           # 0–100
    reasons: tuple[str, ...]
    alert: bool          # True if score >= alert_threshold

    @property
    def severity(self) -> str:
        if self.score >= 80:
            return "high"
        if self.score >= 50:
            return "medium"
        if self.score >= 20:
            return "low"
        return "ok"


# Operator baseline — populated by the scanner timer (grgsm_scanner sweep).
# v0.1 keeps an empty baseline; the loaded CSV / SQLite payload is wired in v0.2.
@dataclass
class Baseline:
    known_cids: frozenset[tuple[int, int]] = frozenset()  # {(lac, cid)}
    operator_mcc_mnc: tuple[int, int] = (0, 0)
    plan_arfcns: frozenset[int] = frozenset()


def score(obs: GsmCellObservation, baseline: Baseline,
          alert_threshold: int = 70) -> CellScore:
    """v0.1.0 stub: returns score=0 for every observation.

    The heuristic battery lands in v0.2. The signature here is the
    contract — callers depend on `score`, `reasons`, `alert`, and
    `severity` already in v0.1.
    """
    return CellScore(
        cell_key=obs.key,
        score=0,
        reasons=("v0.1.0 scaffold: 8-heuristic engine not yet wired",),
        alert=False,
    )
