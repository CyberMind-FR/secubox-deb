# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
Privacy invariant tests — the auditable structural proofs of:
  - PROD mode never stores plaintext IMSI/TMSI/IMEI
  - GsmCellObservation has no subscriber-bound field
  - Anonymizer is deterministic + non-reversible (HMAC properties)
  - LAB mode is gated behind explicit mode flip

Per spec §6.2 + §11 (privacy-by-design + non-regression confidentiality test).
"""

import sys
from dataclasses import fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from sentinelle_gsm.observer import (
    ANON_TRUNCATE_HEX,
    CAPTURES_PLAINTEXT_IMSI,
    Anonymizer,
    GsmCellObservation,
    Mode,
)

# Subscriber-bound identifier name fragments. The frozen dataclass must
# not have any field name matching these.
SUBSCRIBER_ID_TOKENS = (
    "imsi", "tmsi", "imei", "msisdn", "iccid", "esn", "meid",
    "subscriber", "phone_number", "msrn", "guti",
)


def test_capture_flag_is_false():
    """Exposed via /api/v1/sensor/gsm/status. Must be False."""
    assert CAPTURES_PLAINTEXT_IMSI is False


def test_gsm_cell_observation_has_no_subscriber_fields():
    for f in fields(GsmCellObservation):
        lower = f.name.lower()
        for tok in SUBSCRIBER_ID_TOKENS:
            assert tok not in lower, (
                f"GsmCellObservation.{f.name} looks like a subscriber id "
                f"(matched '{tok}')"
            )


def test_anonymizer_is_deterministic():
    """Same input + same key → same output. Required for dedupe/counting."""
    a = Anonymizer.ephemeral()
    h1 = a.anonymize("208012345678901")  # synthetic IMSI
    h2 = a.anonymize("208012345678901")
    assert h1 == h2
    assert h1 != "208012345678901"  # NEVER plaintext
    assert len(h1) == ANON_TRUNCATE_HEX


def test_anonymizer_distinct_keys_produce_distinct_outputs():
    """Two different installs (different HMAC keys) → uncorrelated tokens."""
    a1 = Anonymizer.ephemeral()
    a2 = Anonymizer.ephemeral()
    h1 = a1.anonymize("208012345678901")
    h2 = a2.anonymize("208012345678901")
    assert h1 != h2  # key-bound, not a global hash


def test_lab_passthrough_refused_in_prod_mode():
    """The critical regression test: PROD must never leak plaintext.

    lab_passthrough() raises immediately when called outside LAB mode.
    No silent fallback, no implicit anonymization — explicit refusal.
    """
    a = Anonymizer.ephemeral(mode=Mode.PROD)
    with pytest.raises(RuntimeError, match="LAB"):
        a.lab_passthrough("208012345678901")


def test_lab_passthrough_works_in_lab_mode():
    """LAB is allowed, but only after explicit flip."""
    a = Anonymizer.ephemeral(mode=Mode.LAB)
    assert a.lab_passthrough("208012345678901") == "208012345678901"


def test_default_mode_is_prod():
    """Anonymizer constructed without arg must default to PROD."""
    a = Anonymizer.ephemeral()
    assert a.mode is Mode.PROD


def test_anonymizer_rejects_short_keys(tmp_path):
    """A 1-byte key MUST be refused — HMAC-SHA256 needs 32 bytes for the
    invariant to actually mean anything."""
    p = tmp_path / "short-key"
    p.write_bytes(b"x")
    with pytest.raises(ValueError, match=r"32"):
        Anonymizer.from_file(p)


# ---------------------------------------------------------------------------
# v0.2.0 — Alert + TrustedPhone + AlertSink privacy invariants
# ---------------------------------------------------------------------------


def test_alert_dataclass_has_no_plaintext_fields():
    """Alert may only carry the HMAC-truncated `subscriber_hash` — never a
    plaintext subscriber identifier."""
    from sentinelle_gsm.alert_sink import Alert

    field_names = {f.name for f in fields(Alert)}
    forbidden = {"imsi", "imei", "tmsi", "msisdn", "iccid", "subscriber_id"}
    assert field_names.isdisjoint(forbidden), (
        f"Alert has forbidden plaintext-identifier fields: "
        f"{field_names & forbidden}"
    )
    assert "subscriber_hash" in field_names


def test_trusted_phone_dataclass_only_stores_hash():
    """TrustedPhone persists ONLY the HMAC hash, never the plaintext IMSI."""
    from sentinelle_gsm.trusted import TrustedPhone

    field_names = {f.name for f in fields(TrustedPhone)}
    assert "imsi" not in field_names
    assert "imsi_hash" in field_names


def test_alert_sink_refuses_plaintext_imsi(tmp_path):
    """AlertSink.write() must refuse any Alert whose textual fields contain
    a 15-digit token (the plaintext-IMSI shape)."""
    from sentinelle_gsm.alert_sink import Alert, AlertSink

    sink = AlertSink(tmp_path / "alerts.db")
    a = Alert(
        cell_id="208-01-100-12345",
        arfcn=124,
        score=80,
        reason="saw 208201234567890 in paging request",
    )
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        sink.write(a)


# ---------------------------------------------------------------------------
# v0.3.0 — Observation + Sighting + PagingEvent privacy invariants
# ---------------------------------------------------------------------------


def test_observation_has_no_plaintext_fields():
    from sentinelle_gsm.gsmtap_listener import Observation
    from dataclasses import fields
    names = {f.name for f in fields(Observation)}
    forbidden = {"imsi", "tmsi", "imei", "msisdn", "iccid", "subscriber_id"}
    assert names.isdisjoint(forbidden), \
        f"Observation has forbidden plaintext-identifier fields: {names & forbidden}"
    assert "subscriber_hash" in names, \
        "Observation must expose subscriber_hash for HMAC-truncated identifiers"


def test_paging_event_only_stores_hash():
    from sentinelle_gsm.observations import PagingEvent
    from dataclasses import fields
    names = {f.name for f in fields(PagingEvent)}
    forbidden = {"imsi", "tmsi", "imei", "msisdn", "iccid"}
    assert names.isdisjoint(forbidden), \
        f"PagingEvent has forbidden plaintext-identifier fields: {names & forbidden}"
    assert "subscriber_hash" in names


def test_observations_db_refuses_plaintext_imsi(tmp_path):
    from sentinelle_gsm.observations import ObservationsDB, PagingEvent
    import pytest
    db = ObservationsDB(tmp_path / "obs.db")
    e = PagingEvent(
        ts=0.0,
        cell_id="208-01-100-1",
        subscriber_hash="208201234567890",   # 15 digits = plaintext IMSI shape
        request_type="paging-imsi",
    )
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        db.record_paging(e)


# ---------------------------------------------------------------------------
# v0.3.1 — L3 decode + baseline + scoring engine privacy invariants
# ---------------------------------------------------------------------------


def test_l3_decode_returns_no_plaintext_fields():
    from sentinelle_gsm.l3_decode import PagedIdentity, ParsedPagingRequest, CellInfo
    from dataclasses import fields
    for cls in (PagedIdentity, ParsedPagingRequest, CellInfo):
        names = {f.name for f in fields(cls)}
        forbidden = {"imsi", "tmsi", "imei", "msisdn", "iccid", "subscriber_id"}
        assert names.isdisjoint(forbidden), \
            f"{cls.__name__} has plaintext id fields: {names & forbidden}"


def test_paging_request_hashes_paged_identities():
    from sentinelle_gsm.observer import Anonymizer
    from sentinelle_gsm.l3_decode import L3Decode, MID_TYPE_TMSI
    anon = Anonymizer(b"x" * 32)
    dec = L3Decode(anon)
    # Build a paging request type 1 with a TMSI
    tmsi = b"\xDE\xAD\xBE\xEF"
    mid = b"\x05\xF4" + tmsi          # length=5 + body=[type_byte + 4 bytes TMSI]
    raw = b"\x06\x21\x00" + mid       # L3 header + page_mode + MID
    frame = dec.parse(raw)
    assert frame.paging is not None
    assert len(frame.paging.identities) >= 1
    pid = frame.paging.identities[0]
    # The plaintext TMSI bytes (as hex string) MUST NOT appear in the hash
    assert tmsi.hex() not in pid.subscriber_hash
    assert pid.id_type == MID_TYPE_TMSI


def test_cell_baseline_has_no_subscriber_fields():
    from sentinelle_gsm.baseline import BaselineCell
    from dataclasses import fields
    names = {f.name for f in fields(BaselineCell)}
    forbidden = {"imsi", "tmsi", "imei", "subscriber_hash", "subscriber_id", "msisdn", "iccid"}
    assert names.isdisjoint(forbidden), \
        f"BaselineCell has forbidden id-related fields: {names & forbidden}"


def test_scoring_engine_reasons_contain_no_plaintext_imsi():
    """The reason strings produced by each heuristic must NOT contain
    a 15-digit token (plaintext IMSI shape). All identifiers in reasons
    should already be hashed/truncated."""
    import re
    from sentinelle_gsm.observer import Anonymizer
    from sentinelle_gsm.scoring_engine import ScoringEngine
    from sentinelle_gsm.baseline import CellBaseline
    from sentinelle_gsm.observations import ObservationsDB
    from sentinelle_gsm.l3_decode import CellInfo, ParsedPagingRequest, PagedIdentity, MID_TYPE_TMSI
    import tempfile, pathlib

    with tempfile.TemporaryDirectory() as td:
        obs_db = ObservationsDB(pathlib.Path(td) / "obs.db")
        baseline = CellBaseline(obs_db._db)
        engine = ScoringEngine(baseline)

        # Feed an observation that triggers identity_request_abuse with a TMSI
        # hash like '208201234567890ABCDEF' — the hash output happens to
        # contain 15 digits in the abusive case; the reason should still
        # not echo those raw digits unguarded.
        # Just verify NO reason string from a typical observation flow
        # matches the plaintext-IMSI shape \b\d{15}\b.
        ci = CellInfo(mcc=208, mnc=1, lac=100, ci=12345)
        pg = ParsedPagingRequest(
            paging_type=0x21,
            identities=[PagedIdentity(id_type=MID_TYPE_TMSI, subscriber_hash="abc123def456")],
        )
        result = engine.evaluate(ci, pg, raw_arfcn=42)
        for reason in result.reasons:
            assert not re.search(r"\b\d{15}\b", reason), \
                f"scoring reason contains plaintext-IMSI shape: {reason!r}"
