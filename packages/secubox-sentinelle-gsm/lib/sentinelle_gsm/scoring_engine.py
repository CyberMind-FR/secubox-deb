# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/scoring_engine.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: sentinelle_gsm.scoring_engine

The v0.3.1 8-heuristic scoring engine for GSM IMSI-catcher detection.

Each heuristic returns a HeuristicResult; ScoringEngine.evaluate() runs
the battery, sums the contributions of the triggered ones, clamps to
[0, 100], and returns a CellScore.

Privacy invariant: this engine NEVER sees plaintext IMSI/TMSI. All
identity material that reaches identity_request_abuse arrives already
hashed (HMAC-trunc, via lib/sentinelle_gsm/l3_decode.py + Anonymizer).
The rolling windows key on `subscriber_hash` strings.

Heuristics (per spec §6.1):

  1. cipher_downgrade       observed A5/X < baseline.cipher_a5
  2. ghost_bts              cell not in baseline AND paging seen
  3. identity_mismatch      observed (mcc, mnc) ≠ baseline (mcc, mnc)
  4. relocalization_storm   > N distinct LACs for cell in W seconds
  5. identity_request_abuse > N paging requests for same subscriber_hash
                            in W seconds
  6. anomalous_neighbours   baseline saw neighbours, current frame empty
  7. t3212_out_of_band      T3212 outside operator-realistic range
  8. orphan_arfcn           FR carrier announces ARFCN outside its plan

Rolling-window state (in-memory ONLY, no DB persistence in v0.3.1):
  _lac_window      cell_id          → deque[(ts, lac)]
  _idreq_window    subscriber_hash  → deque[ts]
  _neighbour_baseline cell_id       → set[int]   (ARFCNs ever seen)
"""

from __future__ import annotations

import copy
import dataclasses
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from sentinelle_gsm.baseline import BaselineCell, CellBaseline
from sentinelle_gsm.l3_decode import CellInfo, ParsedPagingRequest


# ── Public dataclasses ─────────────────────────────────────────────────────


@dataclasses.dataclass
class HeuristicResult:
    name: str
    triggered: bool
    score_contrib: int
    reason: str


@dataclasses.dataclass
class CellScore:
    cell_id: str
    score: int                       # clamped to [0, 100]
    reasons: List[str]
    triggered: List[str]


# ── France GSM-900 / E-GSM ARFCN plan (approximate) ────────────────────────
# Be permissive: only listed (mcc, mnc) pairs are checked. Unknown carriers
# return triggered=False to avoid noise.

CARRIER_ARFCN_PLAN_FR: Dict[str, Dict[Tuple[int, int], Any]] = {
    "Orange":   {(208, 1):  range(1,   75)},
    "SFR":      {(208, 10): range(75,  101)},
    "Bouygues": {(208, 20): list(range(101, 121))},
    "Free":     {(208, 15): list(range(121, 125)) + list(range(975, 1024))},
}


def _expected_arfcns_for(mcc: int, mnc: int) -> Optional[List[int]]:
    """Return the union of allowed ARFCNs for this (mcc, mnc), or None
    if we don't know this carrier (permissive: caller skips the check)."""
    for plan in CARRIER_ARFCN_PLAN_FR.values():
        if (mcc, mnc) in plan:
            return list(plan[(mcc, mnc)])
    return None


# ── ScoringEngine ──────────────────────────────────────────────────────────


class ScoringEngine:
    """Heuristic battery wired against a CellBaseline.

    Construct once; call evaluate() per parsed L3 frame. Rolling-window
    state lives in instance fields — keep a single engine per process.
    """

    DEFAULT_THRESHOLDS: Dict[str, Dict[str, Any]] = {
        "cipher_downgrade":       {"enabled": True, "score": 40},
        "ghost_bts":              {"enabled": True, "score": 35},
        "identity_mismatch":      {"enabled": True, "score": 30},
        "relocalization_storm":   {"enabled": True, "score": 25, "window_s": 60,  "lac_threshold": 3},
        "identity_request_abuse": {"enabled": True, "score": 35, "window_s": 300, "req_threshold": 2},
        "anomalous_neighbours":   {"enabled": True, "score": 15},
        "t3212_out_of_band":      {"enabled": True, "score": 15, "min": 1, "max": 60},
        "orphan_arfcn":           {"enabled": True, "score": 20},
    }

    def __init__(self, baseline: CellBaseline,
                 thresholds: Optional[Dict[str, Dict[str, Any]]] = None):
        self._baseline = baseline
        # Deep-copy defaults so callers can't mutate class state by reference.
        self._thresholds: Dict[str, Dict[str, Any]] = copy.deepcopy(self.DEFAULT_THRESHOLDS)
        if thresholds:
            self.update_thresholds(thresholds)

        # Rolling-window state — in-memory only.
        self._lac_window: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._idreq_window: Dict[str, Deque[float]] = defaultdict(deque)
        self._neighbour_baseline: Dict[str, Set[int]] = {}

    # ── threshold management ──────────────────────────────────────────────

    def thresholds(self) -> Dict[str, Dict[str, Any]]:
        """Return a deep-copy of the effective thresholds."""
        return copy.deepcopy(self._thresholds)

    def update_thresholds(
        self, new: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Per-heuristic deep-merge of `new` into the effective thresholds.

        Allows partial updates: passing
            {"cipher_downgrade": {"score": 50}}
        leaves "enabled" untouched on cipher_downgrade and all other
        heuristics unchanged.
        """
        for h_name, h_update in new.items():
            if not isinstance(h_update, dict):
                continue
            target = self._thresholds.setdefault(h_name, {})
            for k, v in h_update.items():
                target[k] = v
        return self.thresholds()

    # ── main entry point ──────────────────────────────────────────────────

    def evaluate(self,
                 cell_info: Optional[CellInfo],
                 parsed_paging: Optional[ParsedPagingRequest],
                 raw_arfcn: int,
                 raw_neighbours: Optional[Set[int]] = None) -> CellScore:
        """Run all 8 heuristics against the supplied parse result.

        cell_id resolution:
          * If cell_info has (mcc, mnc, lac, ci) → "{mcc}-{mnc}-{lac}-{ci}"
          * Otherwise fall back to "arfcn-{raw_arfcn}" so paging-only
            frames still produce a stable key.
        """
        cell_id = self._cell_id_from_info(cell_info) or f"arfcn-{raw_arfcn}"
        baseline_cell = self._baseline.get(cell_id) if self._baseline else None
        # Only treat as a real baseline once graduated.
        if baseline_cell is not None and not self._baseline.is_baseline(cell_id):
            baseline_cell = None

        results: List[HeuristicResult] = [
            self._h_cipher_downgrade(cell_info, baseline_cell),
            self._h_ghost_bts(cell_id, baseline_cell, parsed_paging),
            self._h_identity_mismatch(cell_info, raw_arfcn, baseline_cell),
            self._h_relocalization_storm(cell_id, cell_info),
            self._h_identity_request_abuse(parsed_paging),
            self._h_anomalous_neighbours(cell_id, raw_neighbours),
            self._h_t3212_out_of_band(cell_info),
            self._h_orphan_arfcn(raw_arfcn, cell_info),
        ]

        total = sum(r.score_contrib for r in results if r.triggered)
        total = min(100, max(0, total))
        triggered = [r.name for r in results if r.triggered]
        reasons = [r.reason for r in results if r.triggered]
        return CellScore(cell_id=cell_id, score=total,
                         reasons=reasons, triggered=triggered)

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _cell_id_from_info(ci: Optional[CellInfo]) -> Optional[str]:
        if ci is None:
            return None
        if (ci.mcc is None or ci.mnc is None
                or ci.lac is None or ci.ci is None):
            return None
        return f"{ci.mcc}-{ci.mnc}-{ci.lac}-{ci.ci}"

    def _t(self, name: str) -> Dict[str, Any]:
        return self._thresholds.get(name, {})

    def _enabled(self, name: str) -> bool:
        return bool(self._t(name).get("enabled", True))

    def _miss(self, name: str) -> HeuristicResult:
        return HeuristicResult(name=name, triggered=False, score_contrib=0, reason="")

    # ── 1. cipher_downgrade ───────────────────────────────────────────────

    def _h_cipher_downgrade(self, cell_info: Optional[CellInfo],
                            baseline_cell: Optional[BaselineCell]) -> HeuristicResult:
        name = "cipher_downgrade"
        if not self._enabled(name):
            return self._miss(name)
        if (baseline_cell is None or baseline_cell.cipher_a5 is None
                or cell_info is None or cell_info.a5_advertised is None):
            return self._miss(name)
        if cell_info.a5_advertised < baseline_cell.cipher_a5:
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(self._t(name).get("score", 40)),
                reason=(f"cipher_downgrade A5/{cell_info.a5_advertised} "
                        f"(baseline A5/{baseline_cell.cipher_a5})"),
            )
        return self._miss(name)

    # ── 2. ghost_bts ──────────────────────────────────────────────────────

    def _h_ghost_bts(self, cell_id: str,
                     baseline_cell: Optional[BaselineCell],
                     parsed_paging: Optional[ParsedPagingRequest]) -> HeuristicResult:
        name = "ghost_bts"
        if not self._enabled(name):
            return self._miss(name)
        if baseline_cell is None and parsed_paging is not None:
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(self._t(name).get("score", 35)),
                reason=f"ghost_bts cell {cell_id} not in baseline (paging seen)",
            )
        return self._miss(name)

    # ── 3. identity_mismatch ──────────────────────────────────────────────

    def _h_identity_mismatch(self, cell_info: Optional[CellInfo],
                             raw_arfcn: int,
                             baseline_cell: Optional[BaselineCell]) -> HeuristicResult:
        name = "identity_mismatch"
        if not self._enabled(name):
            return self._miss(name)
        if (baseline_cell is None or cell_info is None
                or cell_info.mcc is None):
            return self._miss(name)
        if (baseline_cell.mcc, baseline_cell.mnc) != (cell_info.mcc, cell_info.mnc):
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(self._t(name).get("score", 30)),
                reason=(f"identity_mismatch (baseline {baseline_cell.mcc}-"
                        f"{baseline_cell.mnc} vs observed "
                        f"{cell_info.mcc}-{cell_info.mnc} on arfcn {raw_arfcn})"),
            )
        return self._miss(name)

    # ── 4. relocalization_storm ───────────────────────────────────────────

    def _h_relocalization_storm(self, cell_id: str,
                                cell_info: Optional[CellInfo]) -> HeuristicResult:
        name = "relocalization_storm"
        if not self._enabled(name):
            return self._miss(name)
        t = self._t(name)
        window_s = float(t.get("window_s", 60))
        threshold = int(t.get("lac_threshold", 3))
        if cell_info is None or cell_info.lac is None:
            return self._miss(name)
        now = time.time()
        q = self._lac_window[cell_id]
        q.append((now, cell_info.lac))
        cutoff = now - window_s
        while q and q[0][0] < cutoff:
            q.popleft()
        distinct = {lac for _, lac in q}
        if len(distinct) > threshold:
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(t.get("score", 25)),
                reason=(f"relocalization_storm: {len(distinct)} distinct "
                        f"LACs in {int(window_s)}s on cell {cell_id}"),
            )
        return self._miss(name)

    # ── 5. identity_request_abuse ─────────────────────────────────────────

    def _h_identity_request_abuse(
        self, parsed_paging: Optional[ParsedPagingRequest]
    ) -> HeuristicResult:
        name = "identity_request_abuse"
        if not self._enabled(name):
            return self._miss(name)
        t = self._t(name)
        window_s = float(t.get("window_s", 300))
        threshold = int(t.get("req_threshold", 2))
        if parsed_paging is None or not parsed_paging.identities:
            return self._miss(name)
        now = time.time()
        cutoff = now - window_s
        worst_hash: Optional[str] = None
        worst_count = 0
        for pid in parsed_paging.identities:
            h = pid.subscriber_hash
            if not h:
                continue
            q = self._idreq_window[h]
            q.append(now)
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) > worst_count:
                worst_count = len(q)
                worst_hash = h
        if worst_hash is not None and worst_count > threshold:
            # Truncate hash to 8 chars for log safety (NEVER plaintext anyway).
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(t.get("score", 35)),
                reason=(f"identity_request_abuse: {worst_count} requests "
                        f"in {int(window_s)}s for subscriber_hash "
                        f"{worst_hash[:8]}"),
            )
        return self._miss(name)

    # ── 6. anomalous_neighbours ───────────────────────────────────────────

    def _h_anomalous_neighbours(self, cell_id: str,
                                raw_neighbours: Optional[Set[int]]) -> HeuristicResult:
        name = "anomalous_neighbours"
        if not self._enabled(name):
            return self._miss(name)
        triggered = False
        prior = self._neighbour_baseline.get(cell_id)
        # Trigger condition: we have a prior neighbour set AND the
        # current frame announces an EMPTY neighbour list.
        if (prior is not None and len(prior) > 0
                and raw_neighbours is not None and raw_neighbours == set()):
            triggered = True
        # Update running baseline AFTER deciding.
        if raw_neighbours is not None:
            self._neighbour_baseline.setdefault(cell_id, set()).update(raw_neighbours)
        if triggered:
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(self._t(name).get("score", 15)),
                reason=(f"anomalous_neighbours: cell {cell_id} previously "
                        f"announced {len(prior)} neighbours, now empty"),
            )
        return self._miss(name)

    # ── 7. t3212_out_of_band ──────────────────────────────────────────────

    def _h_t3212_out_of_band(self, cell_info: Optional[CellInfo]) -> HeuristicResult:
        name = "t3212_out_of_band"
        if not self._enabled(name):
            return self._miss(name)
        t = self._t(name)
        lo = int(t.get("min", 1))
        hi = int(t.get("max", 60))
        if cell_info is None or cell_info.t3212_minutes is None:
            return self._miss(name)
        v = cell_info.t3212_minutes
        if v < lo or v > hi:
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(t.get("score", 15)),
                reason=(f"t3212_out_of_band: {v} min outside [{lo}, {hi}]"),
            )
        return self._miss(name)

    # ── 8. orphan_arfcn ───────────────────────────────────────────────────

    def _h_orphan_arfcn(self, raw_arfcn: int,
                        cell_info: Optional[CellInfo]) -> HeuristicResult:
        name = "orphan_arfcn"
        if not self._enabled(name):
            return self._miss(name)
        if (cell_info is None or cell_info.mcc is None
                or cell_info.mnc is None or cell_info.mcc != 208):
            return self._miss(name)
        expected = _expected_arfcns_for(cell_info.mcc, cell_info.mnc)
        if expected is None:
            # Unknown (mcc, mnc) — permissive, never flag.
            return self._miss(name)
        if raw_arfcn not in expected:
            return HeuristicResult(
                name=name, triggered=True,
                score_contrib=int(self._t(name).get("score", 20)),
                reason=(f"orphan_arfcn: {cell_info.mcc}-{cell_info.mnc} "
                        f"announces ARFCN {raw_arfcn} outside its plan"),
            )
        return self._miss(name)
