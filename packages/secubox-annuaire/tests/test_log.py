# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_log.py
Tests for annuaire.log — append-only BLAKE2b-chained SQLite journal.
All tests follow TDD: written before implementation.
"""
import hashlib
import os
import sqlite3
import pytest

from annuaire.log import Journal
from annuaire.model import Op, GENESIS_HASH
from annuaire.crypto import generate_keypair, sign, did_from_pubkey, canonical_bytes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    """Return a fresh Journal backed by a temp SQLite file."""
    db_path = tmp_path / "test_log.db"
    return Journal(db_path=str(db_path))


@pytest.fixture
def keypair():
    priv, pub = generate_keypair()
    return priv, pub, did_from_pubkey(pub), pub.hex()


def _make_signed_payload(priv_bytes, did, payload_dict):
    """Return (payload_dict, canonical_bytes, sig_hex) ready for Journal.append."""
    cb = canonical_bytes(payload_dict)
    sig_hex = sign(priv_bytes, cb)
    return payload_dict, cb, sig_hex


# ---------------------------------------------------------------------------
# append — builds correct chain
# ---------------------------------------------------------------------------

def test_append_first_entry_has_genesis_prev_hash(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    payload = {"op": "test", "did": did}
    cb = canonical_bytes(payload)
    sig_hex = sign(priv, cb)

    entry = tmp_db.append(
        op=Op.AUTO_ADD,
        payload_type="Identity",
        payload=payload,
        author=did,
        sig=sig_hex,
        author_pubkey_hex=pub_hex,
    )
    assert entry.prev_hash == GENESIS_HASH
    assert entry.height == 0


def test_append_second_entry_chains_to_first(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    payload1 = {"seq": 1, "did": did}
    cb1 = canonical_bytes(payload1)
    sig1 = sign(priv, cb1)
    entry1 = tmp_db.append(Op.AUTO_ADD, "Identity", payload1, did, sig1,
                            author_pubkey_hex=pub_hex)

    payload2 = {"seq": 2, "did": did}
    cb2 = canonical_bytes(payload2)
    sig2 = sign(priv, cb2)
    entry2 = tmp_db.append(Op.ATTEST, "Attestation", payload2, did, sig2,
                            author_pubkey_hex=pub_hex)

    assert entry2.prev_hash == entry1.entry_hash
    assert entry2.height == 1


def test_append_entry_hash_is_computed_correctly(tmp_db, keypair):
    from annuaire.model import compute_entry_hash
    priv, pub, did, pub_hex = keypair
    payload = {"x": "y"}
    cb = canonical_bytes(payload)
    sig_hex = sign(priv, cb)

    entry = tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig_hex,
                          author_pubkey_hex=pub_hex)

    expected_hash = compute_entry_hash(GENESIS_HASH, cb, sig_hex)
    assert entry.entry_hash == expected_hash


def test_append_rejects_bad_signature(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    _priv2, pub2 = generate_keypair()
    payload = {"x": "y"}
    cb = canonical_bytes(payload)
    # Sign with a different key — sig won't match author's pubkey
    sig_hex = sign(_priv2, cb)

    with pytest.raises(ValueError, match="signature"):
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig_hex,
                      author_pubkey_hex=pub_hex)


# ---------------------------------------------------------------------------
# verify_chain — clean chain passes
# ---------------------------------------------------------------------------

def test_verify_chain_empty_journal_is_ok(tmp_db):
    ok, broken_at = tmp_db.verify_chain()
    assert ok is True
    assert broken_at is None


def test_verify_chain_passes_on_clean_chain(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    for i in range(5):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                      author_pubkey_hex=pub_hex)

    ok, broken_at = tmp_db.verify_chain()
    assert ok is True
    assert broken_at is None


# ---------------------------------------------------------------------------
# verify_chain — TAMPER DETECTION (the critical test)
# ---------------------------------------------------------------------------

def test_verify_chain_detects_tampered_entry_hash(tmp_db, keypair):
    """Mutate a stored entry_hash and verify_chain must return (False, N)."""
    priv, pub, did, pub_hex = keypair
    for i in range(3):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                      author_pubkey_hex=pub_hex)

    # Direct DB surgery — tamper with the first entry's stored entry_hash
    con = sqlite3.connect(str(tmp_db.db_path))
    con.execute(
        "UPDATE log SET entry_hash = ? WHERE height = 0",
        ("dead" * 16,),  # 64-char hex replacement
    )
    con.commit()
    con.close()

    ok, broken_at = tmp_db.verify_chain()
    assert ok is False
    assert broken_at == 0, f"Expected tamper at height 0, got broken_at={broken_at}"


def test_verify_chain_detects_tampered_payload(tmp_db, keypair):
    """Mutate the payload column — recomputed hash diverges from stored hash."""
    priv, pub, did, pub_hex = keypair
    for i in range(3):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                      author_pubkey_hex=pub_hex)

    # Tamper payload at height=1
    con = sqlite3.connect(str(tmp_db.db_path))
    con.execute(
        'UPDATE log SET payload = ? WHERE height = 1',
        ('{"i": 99}',),
    )
    con.commit()
    con.close()

    ok, broken_at = tmp_db.verify_chain()
    assert ok is False
    assert broken_at == 1, f"Expected tamper at height 1, got broken_at={broken_at}"


def test_verify_chain_detects_broken_prev_hash_link(tmp_db, keypair):
    """Mutate prev_hash of height=2 — the chain link is severed."""
    priv, pub, did, pub_hex = keypair
    for i in range(3):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                      author_pubkey_hex=pub_hex)

    con = sqlite3.connect(str(tmp_db.db_path))
    con.execute(
        "UPDATE log SET prev_hash = ? WHERE height = 2",
        ("0" * 64,),
    )
    con.commit()
    con.close()

    ok, broken_at = tmp_db.verify_chain()
    assert ok is False
    assert broken_at == 2


# ---------------------------------------------------------------------------
# Append-only — no delete/update API exposed
# ---------------------------------------------------------------------------

def test_journal_has_no_delete_method(tmp_db):
    assert not hasattr(tmp_db, "delete"), "Journal must not expose a delete method"


def test_journal_has_no_update_method(tmp_db):
    assert not hasattr(tmp_db, "update"), "Journal must not expose an update method"


# ---------------------------------------------------------------------------
# merkle_root changes when an entry is added
# ---------------------------------------------------------------------------

def test_merkle_root_on_empty_journal_returns_genesis(tmp_db):
    root = tmp_db.merkle_root()
    assert root == GENESIS_HASH


def test_merkle_root_changes_when_entry_appended(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    root_before = tmp_db.merkle_root()

    payload = {"x": 1}
    cb = canonical_bytes(payload)
    sig = sign(priv, cb)
    tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                  author_pubkey_hex=pub_hex)

    root_after = tmp_db.merkle_root()
    assert root_before != root_after


def test_merkle_root_is_consistent_across_same_entries(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    for i in range(4):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                      author_pubkey_hex=pub_hex)

    root1 = tmp_db.merkle_root()
    root2 = tmp_db.merkle_root()
    assert root1 == root2, "Merkle root must be deterministic for same entries"


# ---------------------------------------------------------------------------
# tip and iter_entries
# ---------------------------------------------------------------------------

def test_tip_returns_none_on_empty_journal(tmp_db):
    assert tmp_db.tip() is None


def test_tip_returns_last_entry(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    last = None
    for i in range(3):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        last = tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                             author_pubkey_hex=pub_hex)

    assert tmp_db.tip().height == last.height


def test_iter_entries_yields_all_in_order(tmp_db, keypair):
    priv, pub, did, pub_hex = keypair
    for i in range(5):
        payload = {"i": i}
        cb = canonical_bytes(payload)
        sig = sign(priv, cb)
        tmp_db.append(Op.AUTO_ADD, "Identity", payload, did, sig,
                      author_pubkey_hex=pub_hex)

    entries = list(tmp_db.iter_entries())
    assert len(entries) == 5
    heights = [e.height for e in entries]
    assert heights == list(range(5)), "iter_entries must yield entries in height order"
