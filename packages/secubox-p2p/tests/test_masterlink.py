# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: masterlink tests
Tests for master election function, role enum, and term store.
"""
import pytest
from api.masterlink import Role, elect, TermStore


def test_elect_lowest_priority_wins():
    """Lowest priority value wins the election."""
    peers = [
        {"node_id_hex": "aaa", "priority": 100},
        {"node_id_hex": "bbb", "priority": 50},
        {"node_id_hex": "ccc", "priority": 100},
    ]
    assert elect(peers) == "bbb"


def test_elect_tie_broken_by_node_id():
    """When priorities tie, lexicographically smaller node_id_hex wins."""
    peers = [
        {"node_id_hex": "zzz", "priority": 50},
        {"node_id_hex": "aaa", "priority": 50},
    ]
    assert elect(peers) == "aaa"


def test_elect_stable_under_reordering():
    """elect() result is stable when input list is reordered."""
    peers = [
        {"node_id_hex": "zzz", "priority": 50},
        {"node_id_hex": "aaa", "priority": 50},
    ]
    forward = elect(peers)
    reverse = elect(list(reversed(peers)))
    assert forward == reverse == "aaa"


def test_elect_empty_raises():
    """elect() raises ValueError on empty peer list."""
    with pytest.raises(ValueError):
        elect([])


def test_termstore_monotonic_and_persisted(tmp_path):
    """TermStore increments monotonically and persists to disk."""
    term_file = tmp_path / "term"
    ts = TermStore(term_file)
    assert ts.term == 0

    # Bump twice
    assert ts.bump() == 1
    assert ts.bump() == 2

    # Create new instance from same file
    ts2 = TermStore(term_file)
    assert ts2.term == 2

    # Verify file permissions are 0o600
    assert (term_file.stat().st_mode & 0o777) == 0o600


def test_termstore_set_min_never_backwards(tmp_path):
    """set_min() adopts higher terms but never goes backwards."""
    term_file = tmp_path / "t2"
    ts = TermStore(term_file)

    # Bump to term 1
    ts.bump()
    assert ts.term == 1

    # set_min to higher term
    ts.set_min(5)
    assert ts.term == 5

    # Try to set_min to lower term (should not go backwards)
    ts.set_min(3)
    assert ts.term == 5


def test_role_enum_values():
    """Role enum has correct string values."""
    assert Role.MASTER.value == "master"
    assert Role.SATELLITE.value == "satellite"
    assert Role.CANDIDATE.value == "candidate"
