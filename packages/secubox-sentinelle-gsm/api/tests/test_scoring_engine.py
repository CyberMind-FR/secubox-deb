# packages/secubox-sentinelle-gsm/api/tests/test_scoring_engine.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
Tests for ScoringEngine — the 8-heuristic detector.

Each heuristic gets one focused test; aggregation + threshold merge get
one each. The CellBaseline is backed by a real sqlite (via ObservationsDB)
so we exercise the same code path the consume loop hits in production.
"""

from __future__ import annotations

import pytest

from sentinelle_gsm.baseline import CellBaseline
from sentinelle_gsm.l3_decode import (
    MID_TYPE_TMSI,
    CellInfo,
    PagedIdentity,
    ParsedPagingRequest,
)
from sentinelle_gsm.observations import ObservationsDB
from sentinelle_gsm.scoring_engine import (
    CellScore,
    HeuristicResult,
    ScoringEngine,
)


def _graduate(baseline: CellBaseline, cell_id: str, **kwargs) -> None:
    """Hit consider() enough times to graduate the cell to baseline."""
    for _ in range(CellBaseline.LEARN_THRESHOLD):
        baseline.consider(cell_id, **kwargs)
    assert baseline.is_baseline(cell_id) is True


@pytest.fixture
def scoring_engine_factory(tmp_path):
    """Return a factory that yields (engine, baseline). Fresh DB per call."""
    created = []

    def _make(thresholds=None):
        db_path = tmp_path / f"obs-{len(created)}.db"
        obs = ObservationsDB(db_path)
        baseline = CellBaseline(obs._db)
        engine = ScoringEngine(baseline, thresholds=thresholds)
        created.append((obs, baseline, engine))
        return engine, baseline

    return _make


# ── 1. cipher_downgrade ────────────────────────────────────────────────────


def test_cipher_downgrade(scoring_engine_factory):
    """Baseline has A5/3 for cell. Observed A5/1 → triggered."""
    engine, baseline = scoring_engine_factory()
    cell_id = "208-1-100-12345"
    _graduate(baseline, cell_id, mcc=208, mnc=1, lac=100, arfcn=42, cipher_a5=3)
    obs = CellInfo(mcc=208, mnc=1, lac=100, ci=12345, a5_advertised=1)
    score = engine.evaluate(obs, None, raw_arfcn=42)
    assert "cipher_downgrade" in score.triggered
    assert score.score >= 40
    assert any("A5/1" in r and "A5/3" in r for r in score.reasons)


# ── 2. ghost_bts ───────────────────────────────────────────────────────────


def test_ghost_bts(scoring_engine_factory):
    """Paging on a cell never seen in baseline → triggered."""
    engine, _baseline = scoring_engine_factory()
    paging = ParsedPagingRequest(
        paging_type=0x21,
        identities=[PagedIdentity(id_type=MID_TYPE_TMSI, subscriber_hash="abc12345deadbeef")],
    )
    # cell_info present but with values that resolve to a brand-new cell_id
    info = CellInfo(mcc=208, mnc=1, lac=999, ci=77777)
    score = engine.evaluate(info, paging, raw_arfcn=42)
    assert "ghost_bts" in score.triggered
    assert score.score >= 35


# ── 3. identity_mismatch ───────────────────────────────────────────────────


def test_identity_mismatch(scoring_engine_factory):
    """Baseline says 208-1; observed says 208-20 on same cell_id → triggered."""
    engine, baseline = scoring_engine_factory()
    cell_id = "208-1-200-23456"
    _graduate(baseline, cell_id, mcc=208, mnc=1, lac=200, arfcn=50, cipher_a5=3)
    # Same cell_id, but advertise a different MNC — IMSI-catcher impersonation.
    obs = CellInfo(mcc=208, mnc=20, lac=200, ci=23456, a5_advertised=3)
    # cell_id from CellInfo would now be "208-20-200-23456", which doesn't
    # match baseline. To exercise identity_mismatch specifically, override
    # by graduating BOTH (matching observed cell_id) with the baseline mcc/mnc.
    # Simpler: register baseline against the observed cell_id with conflicting (mcc, mnc).
    cell_id_observed = "208-20-200-23456"
    _graduate(baseline, cell_id_observed, mcc=208, mnc=1, lac=200, arfcn=50, cipher_a5=3)
    score = engine.evaluate(obs, None, raw_arfcn=50)
    assert "identity_mismatch" in score.triggered
    assert score.score >= 30


# ── 4. relocalization_storm ────────────────────────────────────────────────


def test_relocalization_storm(scoring_engine_factory):
    """> 3 distinct LACs for same cell_id within window → triggered."""
    engine, _baseline = scoring_engine_factory()
    # Same (mcc, mnc, ci) but four different LACs in quick succession.
    last_score: CellScore | None = None
    for lac in (100, 200, 300, 400):
        info = CellInfo(mcc=208, mnc=1, lac=lac, ci=42)
        last_score = engine.evaluate(info, None, raw_arfcn=10)
    assert last_score is not None
    # Each LAC produces a different cell_id; relocalization_storm tracks per
    # cell_id, so we need to push multiple LACs against the SAME cell_id.
    # Reset and do it correctly: keep cell_id stable by feeding through the
    # paging-only fallback ("arfcn-10") with varying LAC values that still
    # produce the same cell_id key. The cell_id_from_info path only triggers
    # when all four (mcc, mnc, lac, ci) are present, so a fixed ARFCN with
    # NO complete CellInfo will share the fallback key.
    engine2, _ = scoring_engine_factory()
    for lac in (100, 200, 300, 400):
        # No ci → cell_id falls back to "arfcn-10"
        info = CellInfo(mcc=208, mnc=1, lac=lac)
        result = engine2.evaluate(info, None, raw_arfcn=10)
    assert "relocalization_storm" in result.triggered
    assert result.score >= 25


# ── 5. identity_request_abuse ──────────────────────────────────────────────


def test_identity_request_abuse(scoring_engine_factory):
    """> 2 paging requests for same subscriber_hash within 300s → triggered."""
    engine, _baseline = scoring_engine_factory()
    h = "deadbeefcafef00d"

    def _paging():
        return ParsedPagingRequest(
            paging_type=0x21,
            identities=[PagedIdentity(id_type=MID_TYPE_TMSI, subscriber_hash=h)],
        )

    info = CellInfo(mcc=208, mnc=1, lac=100, ci=42)
    engine.evaluate(info, _paging(), raw_arfcn=10)
    engine.evaluate(info, _paging(), raw_arfcn=10)
    score = engine.evaluate(info, _paging(), raw_arfcn=10)   # 3rd → > threshold 2
    assert "identity_request_abuse" in score.triggered
    assert score.score >= 35
    # subscriber_hash truncated in reason — no plaintext leakage anyway.
    assert any(h[:8] in r for r in score.reasons)


# ── 6. anomalous_neighbours ────────────────────────────────────────────────


def test_anomalous_neighbours(scoring_engine_factory):
    """Previously announced neighbours, now empty set → triggered."""
    engine, _baseline = scoring_engine_factory()
    info = CellInfo(mcc=208, mnc=1, lac=100, ci=42)
    # First seed the running neighbour baseline.
    engine.evaluate(info, None, raw_arfcn=10, raw_neighbours={50, 60, 70})
    # Now the cell announces nothing — drop is suspicious.
    score = engine.evaluate(info, None, raw_arfcn=10, raw_neighbours=set())
    assert "anomalous_neighbours" in score.triggered
    assert score.score >= 15


# ── 7. t3212_out_of_band ───────────────────────────────────────────────────


def test_t3212_out_of_band(scoring_engine_factory):
    """T3212 = 120 min (above max=60) → triggered."""
    engine, _baseline = scoring_engine_factory()
    info = CellInfo(mcc=208, mnc=1, lac=100, ci=42, t3212_minutes=120)
    score = engine.evaluate(info, None, raw_arfcn=10)
    assert "t3212_out_of_band" in score.triggered
    assert score.score >= 15
    assert any("120" in r for r in score.reasons)


# ── 8. orphan_arfcn ────────────────────────────────────────────────────────


def test_orphan_arfcn(scoring_engine_factory):
    """Orange (208-1) announces ARFCN 800 (outside 1-74) → triggered."""
    engine, _baseline = scoring_engine_factory()
    info = CellInfo(mcc=208, mnc=1, lac=100, ci=42)
    score = engine.evaluate(info, None, raw_arfcn=800)
    assert "orphan_arfcn" in score.triggered
    assert score.score >= 20


def test_orphan_arfcn_unknown_carrier_permissive(scoring_engine_factory):
    """Unknown MCC/MNC pair → NOT flagged (permissive)."""
    engine, _baseline = scoring_engine_factory()
    info = CellInfo(mcc=999, mnc=99, lac=100, ci=42)
    score = engine.evaluate(info, None, raw_arfcn=4242)
    assert "orphan_arfcn" not in score.triggered


# ── aggregation ────────────────────────────────────────────────────────────


def test_evaluate_aggregates_and_clamps(scoring_engine_factory):
    """Trigger several heuristics at once; sum is clamped to 100."""
    engine, baseline = scoring_engine_factory()
    cell_id = "208-1-100-12345"
    _graduate(baseline, cell_id, mcc=208, mnc=1, lac=100, arfcn=800, cipher_a5=3)
    # Re-graduate with a DIFFERENT cell_id that matches the observation,
    # carrying the conflicting baseline (mcc, mnc) so identity_mismatch fires.
    obs_cell_id = "208-20-100-12345"
    _graduate(baseline, obs_cell_id, mcc=208, mnc=1, lac=100, arfcn=800, cipher_a5=3)
    # Observation: A5 downgrade + MNC mismatch + orphan ARFCN + bad T3212
    info = CellInfo(mcc=208, mnc=20, lac=100, ci=12345,
                    a5_advertised=1, t3212_minutes=999)
    score = engine.evaluate(info, None, raw_arfcn=800)
    # cipher_downgrade(40) + identity_mismatch(30) + orphan_arfcn(20)
    # + t3212_out_of_band(15) = 105 → clamped to 100.
    assert score.score == 100
    assert "cipher_downgrade" in score.triggered
    assert "identity_mismatch" in score.triggered
    assert "orphan_arfcn" in score.triggered
    assert "t3212_out_of_band" in score.triggered
    assert len(score.reasons) == len(score.triggered)


# ── threshold merging ─────────────────────────────────────────────────────


def test_update_thresholds_deep_merge(scoring_engine_factory):
    """update_thresholds() merges per-heuristic; untouched fields stay."""
    engine, _baseline = scoring_engine_factory()
    # Override only the score for cipher_downgrade; "enabled" stays True.
    effective = engine.update_thresholds({"cipher_downgrade": {"score": 55}})
    assert effective["cipher_downgrade"]["score"] == 55
    assert effective["cipher_downgrade"]["enabled"] is True
    # Other heuristics untouched.
    assert effective["ghost_bts"]["score"] == 35
    # Disable orphan_arfcn entirely.
    effective2 = engine.update_thresholds({"orphan_arfcn": {"enabled": False}})
    assert effective2["orphan_arfcn"]["enabled"] is False
    assert effective2["orphan_arfcn"]["score"] == 20    # untouched
    # Effect on evaluate(): orphan_arfcn no longer fires even on a bad ARFCN.
    _, baseline = scoring_engine_factory()
    engine2 = ScoringEngine(baseline)
    engine2.update_thresholds({"orphan_arfcn": {"enabled": False}})
    info = CellInfo(mcc=208, mnc=1, lac=100, ci=42)
    score = engine2.evaluate(info, None, raw_arfcn=800)
    assert "orphan_arfcn" not in score.triggered
