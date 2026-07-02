# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: masterlink tests
Tests for master election function, role enum, and term store.
"""
import pytest
from api.masterlink import Role, elect, TermStore, MasterLink


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


def test_silent_master_triggers_self_election(tmp_path):
    """A lone node with no peers elects itself master after the election timeout."""
    sends = []
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], sends.append,
        TermStore(tmp_path / "term1"), clock, election_timeout=15,
    )
    assert ml.role == Role.SATELLITE

    t[0] += 20  # advance past election_timeout
    ml.tick()

    assert ml.role == Role.MASTER
    assert ml.term > 0
    assert len(sends) == 1
    assert sends[0]["master_id"] == "aa"


def test_stale_heartbeat_ignored(tmp_path):
    """A heartbeat with a lower term than ours is ignored."""
    sends = []
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], sends.append,
        TermStore(tmp_path / "term2"), clock, election_timeout=15,
    )
    t[0] += 20
    ml.tick()
    assert ml.role == Role.MASTER
    term_after_election = ml.term

    ml.on_heartbeat({"term": term_after_election - 1, "master_id": "bb", "ts": 1})

    assert ml.role == Role.MASTER
    assert ml.master_id == "aa"


def test_higher_term_heartbeat_demotes_master(tmp_path):
    """A heartbeat carrying a strictly higher term demotes us and adopts the new master."""
    sends = []
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], sends.append,
        TermStore(tmp_path / "term3"), clock, election_timeout=15,
    )
    t[0] += 20
    ml.tick()
    assert ml.role == Role.MASTER

    higher_term = ml.term + 1
    ml.on_heartbeat({"term": higher_term, "master_id": "bb", "ts": 1})

    assert ml.role == Role.SATELLITE
    assert ml.master_id == "bb"
    assert ml.term == higher_term


def test_election_picks_lowest_priority_peer_not_self(tmp_path):
    """When a peer has lower priority than us, it wins the election, not us."""
    sends = []
    t = [1000.0]
    clock = lambda: t[0]
    ts = TermStore(tmp_path / "term4")
    ml = MasterLink(
        "aa", 100, lambda: [{"node_id_hex": "bb", "priority": 10}], sends.append,
        ts, clock, election_timeout=15,
    )
    initial_term = ml.term

    t[0] += 20
    ml.tick()

    assert ml.role == Role.SATELLITE
    assert ml.term > initial_term


def test_master_tick_emits_heartbeat(tmp_path):
    """A node already in MASTER role emits exactly one heartbeat per tick()."""
    sends = []
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], sends.append,
        TermStore(tmp_path / "term5"), clock, election_timeout=15,
    )
    ml.role = Role.MASTER
    sends.clear()

    ml.tick()

    assert len(sends) == 1
    assert sends[0]["master_id"] == "aa"


def test_equal_term_collision_leaves_exactly_one_master(tmp_path):
    """Two nodes self-electing at the same term must not both demote on cross-delivery."""
    t = [1000.0]
    clock = lambda: t[0]

    sends_a = []
    ml_a = MasterLink(
        "aa", 100, lambda: [], sends_a.append,
        TermStore(tmp_path / "term_a"), clock, election_timeout=15,
    )
    sends_b = []
    ml_b = MasterLink(
        "bb", 50, lambda: [], sends_b.append,
        TermStore(tmp_path / "term_b"), clock, election_timeout=15,
    )

    t[0] += 20  # advance past election_timeout for both
    ml_a.tick()
    ml_b.tick()

    assert ml_a.role == Role.MASTER
    assert ml_b.role == Role.MASTER
    assert ml_a.term == ml_b.term == 1

    hb_from_a = sends_a[-1]
    hb_from_b = sends_b[-1]

    # Cross-deliver: each hears the other's heartbeat at the same term.
    ml_a.on_heartbeat(hb_from_b)
    ml_b.on_heartbeat(hb_from_a)

    # bb has lower priority (50 < 100) -> bb wins the tie, aa demotes.
    assert ml_b.role == Role.MASTER
    assert ml_a.role == Role.SATELLITE
    assert ml_a.master_id == "bb"


def test_equal_term_winner_ignores_loser_heartbeat(tmp_path):
    """The tie-break winner stays MASTER and does not adopt the loser as master."""
    t = [1000.0]
    clock = lambda: t[0]

    sends_a = []
    ml_a = MasterLink(
        "aa", 100, lambda: [], sends_a.append,
        TermStore(tmp_path / "term_a2"), clock, election_timeout=15,
    )
    sends_b = []
    ml_b = MasterLink(
        "bb", 50, lambda: [], sends_b.append,
        TermStore(tmp_path / "term_b2"), clock, election_timeout=15,
    )

    t[0] += 20
    ml_a.tick()
    ml_b.tick()

    hb_from_a = sends_a[-1]

    ml_b.on_heartbeat(hb_from_a)

    assert ml_b.role == Role.MASTER
    assert ml_b.master_id == "bb"


def test_candidates_skips_malformed_peer(tmp_path):
    """A malformed peer dict from peers_fn is skipped, not raised."""
    t = [1000.0]
    clock = lambda: t[0]
    peers = [{"node_id_hex": "bb", "priority": 10}, {"garbage": 1}]
    ml = MasterLink(
        "aa", 100, lambda: peers, lambda msg: None,
        TermStore(tmp_path / "term_mp"), clock, election_timeout=15,
    )

    t[0] += 20
    ml.tick()  # must not raise

    assert ml.role == Role.SATELLITE
    assert ml.master_id == "bb"


def test_losing_election_sets_master_id(tmp_path):
    """On losing an election, master_id is updated to the elected winner immediately."""
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [{"node_id_hex": "bb", "priority": 1}], lambda msg: None,
        TermStore(tmp_path / "term_mi"), clock, election_timeout=15,
    )

    t[0] += 20
    ml.tick()

    assert ml.role == Role.SATELLITE
    assert ml.master_id == "bb"


def test_malformed_heartbeat_ignored(tmp_path):
    """A malformed heartbeat dict does not raise and does not change role/master_id."""
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], lambda msg: None,
        TermStore(tmp_path / "term_bad_hb"), clock, election_timeout=15,
    )
    role_before, master_before = ml.role, ml.master_id

    ml.on_heartbeat({"bogus": 1})  # must not raise

    assert ml.role == role_before
    assert ml.master_id == master_before
