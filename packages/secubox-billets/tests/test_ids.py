# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from api.ids import is_ulid, new_ulid, ulid_timestamp_ms


def test_ulid_shape():
    u = new_ulid()
    assert len(u) == 26
    assert is_ulid(u)


def test_ulid_is_time_sortable():
    early = new_ulid(ts_ms=1_000_000, randomness=b"\x00" * 10)
    late = new_ulid(ts_ms=2_000_000, randomness=b"\x00" * 10)
    assert early < late


def test_ulid_roundtrips_timestamp():
    u = new_ulid(ts_ms=1_700_000_000_000, randomness=b"\x01" * 10)
    assert ulid_timestamp_ms(u) == 1_700_000_000_000


def test_ulid_rejects_bad_randomness():
    with pytest.raises(ValueError):
        new_ulid(randomness=b"short")


def test_is_ulid_rejects_junk():
    assert not is_ulid("nope")
    assert not is_ulid("I" * 26)  # I is excluded from Crockford alphabet
