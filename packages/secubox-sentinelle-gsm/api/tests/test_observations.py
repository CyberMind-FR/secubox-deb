# packages/secubox-sentinelle-gsm/api/tests/test_observations.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

import pytest
from sentinelle_gsm.observations import ObservationsDB, Sighting, PagingEvent


@pytest.fixture
def db(tmp_path):
    return ObservationsDB(tmp_path / "obs.db")


def test_upsert_new_sighting(db):
    s = Sighting(cell_id="208-01-100-12345", arfcn=124)
    db.upsert_sighting(s)
    out = db.sightings()
    assert len(out) == 1
    assert out[0].cell_id == "208-01-100-12345"
    assert out[0].sighting_count == 1


def test_upsert_bumps_count(db):
    s = Sighting(cell_id="208-01-100-12345", arfcn=124)
    for _ in range(5):
        db.upsert_sighting(s)
    out = db.sightings()
    assert out[0].sighting_count == 5


def test_record_paging_with_hash(db):
    e = PagingEvent(ts=1_700_000_000, cell_id="208-01-100-12345",
                    subscriber_hash="a1b2c3d4e5f6deadbeef0011",
                    request_type="paging-tmsi")
    db.record_paging(e)
    rows = db.paging_for_cell("208-01-100-12345")
    assert len(rows) == 1
    assert rows[0].subscriber_hash.startswith("a1b2")


def test_record_paging_refuses_plaintext_imsi(db):
    e = PagingEvent(ts=1_700_000_000, cell_id="208-01-100-12345",
                    subscriber_hash="208201234567890",  # 15 digits
                    request_type="paging-imsi")
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        db.record_paging(e)
