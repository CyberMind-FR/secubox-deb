# packages/secubox-sentinelle-gsm/api/tests/test_alert_emission.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Integration tests for the v0.3.1 consume-loop alert emission flow.

We drive `_process_observation()` directly with synthesised
Observation instances (rather than booting the UDP listener) so the
tests cover the full L3-decode → baseline → scoring → trusted-match
→ AlertSink path end-to-end, without spawning grgsm_livemon_headless
or binding a real UDP socket.

JWT is bypassed via FastAPI's dependency_overrides — the real JWT
layer lives at nginx + Authelia, not inside the app.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from fastapi.testclient import TestClient

from sentinelle_gsm.alert_sink import AlertSink
from sentinelle_gsm.baseline import CellBaseline
from sentinelle_gsm.gsmtap_listener import Observation
from sentinelle_gsm.l3_decode import L3Decode, MID_TYPE_IMSI
from sentinelle_gsm.observations import ObservationsDB
from sentinelle_gsm.observer import Anonymizer
from sentinelle_gsm.scoring_engine import ScoringEngine
from sentinelle_gsm.trusted import TrustedRegistry


# ─── Synthetic L3 frame builders ──────────────────────────────────────
# Mirror the helpers used in test_l3_decode.py so we can build real
# raw_l3 bytes the decoder will actually parse. Keeping these private
# to this test file rather than importing from test_l3_decode.py — pytest
# resolves the symbol via collection but it makes the dependency explicit.


def _encode_bcd_mcc_mnc(mcc: int, mnc: int) -> bytes:
    """3-byte MCC/MNC encoding per TS 24.008 §10.5.1.3 (2-digit MNC)."""
    m1, m2, m3 = mcc // 100, (mcc // 10) % 10, mcc % 10
    n1, n2 = mnc // 10, mnc % 10
    return bytes([
        (m2 << 4) | m1,
        (0xF << 4) | m3,
        (n2 << 4) | n1,
    ])


def _encode_bcd_imsi_body(imsi: str) -> bytes:
    """Mobile Identity IMSI BCD body."""
    odd = (len(imsi) % 2) == 1
    type_nibble = ((1 if odd else 0) << 3) | MID_TYPE_IMSI
    body = bytearray()
    body.append((int(imsi[0]) << 4) | type_nibble)
    i = 1
    while i < len(imsi):
        low = int(imsi[i])
        high = int(imsi[i + 1]) if (i + 1) < len(imsi) else 0xF
        body.append((high << 4) | low)
        i += 2
    return bytes(body)


def _wrap_mobile_id(body: bytes) -> bytes:
    return bytes([len(body)]) + body


def _build_si6_frame(mcc: int, mnc: int, lac: int, ci: int, a5: int) -> bytes:
    """Build a System Information Type 6 (BCCH) frame with a chosen A5."""
    cell_options = (a5 << 5) & 0xFF
    return (
        b"\x06\x1e"                                  # PD=RR, msg=SI6
        + ci.to_bytes(2, "big")
        + _encode_bcd_mcc_mnc(mcc, mnc)
        + lac.to_bytes(2, "big")
        + bytes([cell_options])
    )


def _build_paging1_frame_with_imsi(imsi: str) -> bytes:
    """Build a Paging Request Type 1 frame carrying ONE IMSI identity."""
    mid_tlv = _wrap_mobile_id(_encode_bcd_imsi_body(imsi))
    return b"\x06\x21" + b"\x00" + mid_tlv         # PD=RR, msg=PR1, page_mode


# ─── Fixture ──────────────────────────────────────────────────────────


@pytest.fixture
def harness(tmp_path):
    """Wire ALL v0.3.1 singletons against tmp_path-backed real implementations.

    Returns the api.main module with all singletons live, JWT bypassed,
    a clean alert sink, and a fresh observations DB / baseline / scoring
    engine. Caller cleans up automatically on yield exit.
    """
    from api import main as api_main

    anonymizer = Anonymizer(b"x" * 32)
    api_main._alert_sink = AlertSink(tmp_path / "alerts.db")
    api_main._trusted_registry = TrustedRegistry(
        tmp_path / "trusted.json", anonymizer
    )
    api_main._obs_db = ObservationsDB(tmp_path / "obs.db")
    api_main._baseline = CellBaseline(api_main._obs_db._db)
    api_main._l3 = L3Decode(anonymizer)
    api_main._scoring = ScoringEngine(api_main._baseline)
    # Lower the alert threshold? No — default 60 is what the plan asks
    # us to test against. Keep it at the module-level default.

    api_main.app.dependency_overrides[api_main.require_jwt] = (
        lambda: {"sub": "tester"}
    )
    try:
        yield api_main, anonymizer
    finally:
        api_main.app.dependency_overrides.clear()
        api_main._alert_sink = None
        api_main._trusted_registry = None
        api_main._obs_db = None
        api_main._baseline = None
        api_main._l3 = None
        api_main._scoring = None


def _run(coro):
    """Execute a coroutine on a fresh event loop.

    A fresh loop per call dodges the "event loop is closed" gotcha when
    pytest-asyncio is not configured and TestClient has already torn down
    its own loop earlier in the test.
    """
    return asyncio.new_event_loop().run_until_complete(coro)


# ─── Tests ────────────────────────────────────────────────────────────


def test_score_below_threshold_no_alert(harness):
    """A bare SI6 frame with no anomalies → score < 60 → NO alert written."""
    api_main, _ = harness
    # Graduate the cell to baseline first so ghost_bts doesn't fire.
    api_main._baseline.consider("208-1-100-12345", mcc=208, mnc=1,
                                 lac=100, arfcn=42, cipher_a5=3)
    api_main._baseline.consider("208-1-100-12345", mcc=208, mnc=1,
                                 lac=100, arfcn=42, cipher_a5=3)
    api_main._baseline.consider("208-1-100-12345", mcc=208, mnc=1,
                                 lac=100, arfcn=42, cipher_a5=3)

    # SI6 with same A5 → no cipher_downgrade, no ghost_bts (in baseline),
    # no identity mismatch (same mcc/mnc), no paging → no abuse.
    raw = _build_si6_frame(mcc=208, mnc=1, lac=100, ci=12345, a5=3)
    obs = Observation(ts=1.0, arfcn=42, frame_nr=0, channel=0x01,
                      sub_type=0, raw_l3=raw)
    _run(api_main._process_observation(obs))
    alerts = api_main._alert_sink.list()
    assert alerts == [], f"unexpected alerts: {alerts}"


def test_score_above_threshold_no_trusted_match_anomaly_only(harness):
    """Score >= 60 + paging present + no trusted match → 1 anomaly-only alert.

    Combined trigger : cipher_downgrade(40) + ghost_bts(35) = 75 ≥ 60.
    The cell is graduated to baseline with A5/3; we then send a frame
    advertising A5/1 (downgrade). Paging is on a different cell_id
    (which is therefore NOT in baseline → ghost_bts).
    """
    api_main, _ = harness
    # Graduate baseline with A5/3
    bl_cell = "208-1-100-12345"
    for _ in range(3):
        api_main._baseline.consider(bl_cell, mcc=208, mnc=1, lac=100,
                                     arfcn=42, cipher_a5=3)
    assert api_main._baseline.is_baseline(bl_cell)

    # Observed SI6 = same cell_id but A5/1 → cipher_downgrade(40)
    # alone is below threshold; verify no premature alert.
    raw_si6 = _build_si6_frame(mcc=208, mnc=1, lac=100, ci=12345, a5=1)
    obs_si = Observation(ts=2.0, arfcn=42, frame_nr=0, channel=0x01,
                         sub_type=0, raw_l3=raw_si6)
    _run(api_main._process_observation(obs_si))

    # Fire a paging frame on a brand-new (un-baselined) cell_id —
    # ghost_bts contributes 35. Paging-only frames don't carry cell_info,
    # so the engine falls back to "arfcn-{arfcn}" → not in baseline.
    raw_pg = _build_paging1_frame_with_imsi("208201234567890")
    obs_pg = Observation(ts=3.0, arfcn=999, frame_nr=0, channel=0x04,
                          sub_type=0, raw_l3=raw_pg)
    _run(api_main._process_observation(obs_pg))

    # First two frames each scored < 60 → no alert yet.
    assert api_main._alert_sink.list() == [], \
        "single triggers must not cross threshold individually"

    # Re-fire the same paging frame twice more → identity_request_abuse
    # (3 reqs in the 300s window, strictly > threshold=2) contributes
    # 35; combined with ghost_bts(35) the cell hits 70 ≥ 60 and an
    # alert is emitted.
    _run(api_main._process_observation(obs_pg))
    _run(api_main._process_observation(obs_pg))
    alerts = api_main._alert_sink.list()
    assert len(alerts) >= 1, f"expected ≥1 alert, got {alerts}"
    a = alerts[0]
    # No trusted IMSI was registered → anomaly-only emission.
    assert a.subscriber_hash is None, f"expected anomaly-only: {a}"
    assert a.trusted_label is None
    assert a.score >= 60


def test_score_above_threshold_with_trusted_match_emits_labeled_alert(harness):
    """Score >= 60 + paging matches trusted phone → labeled alert."""
    api_main, anonymizer = harness
    # Register the trusted phone — same IMSI we'll page below.
    imsi = "208201234567890"
    registered = api_main._trusted_registry.add(imsi, label="ops-phone-1")
    expected_hash = registered.imsi_hash

    # Fire 3 paging frames on the same arfcn (ghost_bts cell) to get
    # identity_request_abuse(35) + ghost_bts(35) = 70.
    raw_pg = _build_paging1_frame_with_imsi(imsi)
    for ts in (10.0, 11.0, 12.0):
        obs = Observation(ts=ts, arfcn=777, frame_nr=0, channel=0x04,
                          sub_type=0, raw_l3=raw_pg)
        _run(api_main._process_observation(obs))

    alerts = api_main._alert_sink.list()
    assert len(alerts) >= 1
    # The labeled alert must surface the trusted match.
    labeled = [a for a in alerts if a.trusted_label is not None]
    assert labeled, f"no labeled alert in {alerts}"
    a = labeled[0]
    assert a.trusted_label == "ops-phone-1"
    assert a.subscriber_hash == expected_hash
    assert a.score >= 60


def test_paging_event_persistence_with_hash(harness):
    """Paging events are persisted with the HMAC hash, never plaintext."""
    api_main, _ = harness
    imsi = "208201234567890"
    raw_pg = _build_paging1_frame_with_imsi(imsi)
    obs = Observation(ts=20.0, arfcn=555, frame_nr=0, channel=0x04,
                      sub_type=0, raw_l3=raw_pg)
    _run(api_main._process_observation(obs))

    # cell_id is fallback (no cell_info on paging-only frame)
    cell_id = "arfcn-555-ch-4"
    events = api_main._obs_db.paging_for_cell(cell_id)
    assert len(events) == 1
    e = events[0]
    # Privacy invariant: the stored hash is NOT the plaintext IMSI.
    assert e.subscriber_hash != imsi
    assert imsi not in e.subscriber_hash
    assert len(e.subscriber_hash) == 16    # ANON_TRUNCATE_HEX
    assert e.request_type == "paging-1"


def test_post_scoring_thresholds_logs_audit(harness, caplog):
    """POST /scoring/thresholds emits an INFO-level audit log entry."""
    api_main, _ = harness
    client = TestClient(api_main.app)

    with caplog.at_level(logging.INFO,
                         logger="secubox.sentinelle-gsm.api"):
        r = client.post(
            "/scoring/thresholds",
            json={"cipher_downgrade": {"score": 55}},
        )
    assert r.status_code == 200
    msgs = [rec.message for rec in caplog.records]
    assert any("scoring thresholds updated" in m for m in msgs), \
        f"expected audit log line, got {msgs}"
    # Threshold body was applied
    assert (
        r.json()["thresholds"]["cipher_downgrade"]["score"] == 55
    )
