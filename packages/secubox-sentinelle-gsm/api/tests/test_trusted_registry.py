# packages/secubox-sentinelle-gsm/api/tests/test_trusted_registry.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

import pytest
from sentinelle_gsm.observer import Anonymizer
from sentinelle_gsm.trusted import TrustedRegistry


@pytest.fixture
def anon():
    return Anonymizer(b"test-secret-32-bytes" + b"\0" * 12)


@pytest.fixture
def reg(tmp_path, anon):
    return TrustedRegistry(tmp_path / "trusted.json", anon)


def test_add_hashes_and_does_not_store_plaintext(reg, tmp_path):
    p = reg.add("208201234567890", "Gerald iPhone")
    assert p.label == "Gerald iPhone"
    assert p.imsi_hash != "208201234567890"
    raw = (tmp_path / "trusted.json").read_text()
    assert "208201234567890" not in raw
    assert p.imsi_hash in raw


def test_lookup_by_hash_finds_added_phone(reg):
    p = reg.add("208201234567890", "iPhone")
    found = reg.lookup_by_hash(p.imsi_hash)
    assert found is not None
    assert found.label == "iPhone"


def test_lookup_by_hash_returns_none_for_unknown(reg):
    reg.add("208201234567890", "iPhone")
    assert reg.lookup_by_hash("0" * 32) is None


def test_delete_removes_entry(reg):
    p = reg.add("208201234567890", "iPhone")
    assert reg.delete(p.id) is True
    assert reg.list() == []
    assert reg.delete("not-an-id") is False


def test_invalid_imsi_rejected(reg):
    with pytest.raises(ValueError):
        reg.add("not-digits", "foo")
    with pytest.raises(ValueError):
        reg.add("123", "too-short")
    with pytest.raises(ValueError):
        reg.add("9" * 16, "too-long")


def test_persistence_across_instances(reg, tmp_path, anon):
    reg.add("208201234567890", "iPhone")
    reg2 = TrustedRegistry(tmp_path / "trusted.json", anon)
    assert len(reg2.list()) == 1
    assert reg2.list()[0].label == "iPhone"
