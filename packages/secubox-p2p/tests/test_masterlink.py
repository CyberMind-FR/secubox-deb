# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: masterlink tests
Tests for master election function, role enum, and term store.
"""
import asyncio

import pytest

import api.dht as dht
from api.masterlink import (
    Role, elect, TermStore, MasterLink,
    sign_heartbeat, verify_heartbeat, peers_from_mesh,
)


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


def test_malformed_priority_ignored(tmp_path):
    """A heartbeat with a non-numeric priority does not raise and is ignored
    (Minor fix: the int(priority) cast must be inside the same try/except
    that guards term/master_id parsing)."""
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], lambda msg: None,
        TermStore(tmp_path / "term_bad_pri"), clock, election_timeout=15,
    )
    role_before, master_before, term_before = ml.role, ml.master_id, ml.term

    ml.on_heartbeat({"term": 1, "master_id": "bb", "priority": "nope"})  # must not raise

    assert ml.role == role_before
    assert ml.master_id == master_before
    assert ml.term == term_before


# -- Signed heartbeats (Ed25519 via api.dht seams) --------------------------


def test_sign_and_verify_heartbeat(monkeypatch):
    """Real Ed25519 roundtrip: sign a heartbeat, verify it, then show tampering
    and a missing sig both fail closed."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    import api.annuaire_client as annuaire_client

    priv_key = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_hex = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    monkeypatch.setattr(annuaire_client, "node_identity", lambda *a, **kw: ("did:x", priv_hex))

    hb = sign_heartbeat(1, "aa", 100, 123.0, id_pubkey=pub_hex)
    assert verify_heartbeat(hb) is True

    tampered = dict(hb, term=2)
    assert verify_heartbeat(tampered) is False

    dropped_sig = dict(hb)
    dropped_sig.pop("sig")
    assert verify_heartbeat(dropped_sig) is False


def test_on_heartbeat_rejects_bad_signature(monkeypatch, tmp_path):
    """A signed heartbeat with a garbage/invalid signature is ignored outright —
    no state change — even though its term/master_id fields look well-formed."""
    monkeypatch.setattr(dht, "_verify_sig", lambda body, sig, pub: False)

    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], lambda msg: None,
        TermStore(tmp_path / "term_bad_sig"), clock, election_timeout=15,
    )
    role_before, master_before, term_before = ml.role, ml.master_id, ml.term

    forged = {
        "t": "heartbeat", "term": term_before + 1, "master_id": "bb",
        "priority": 1, "ts": 1.0, "id_pubkey": "deadbeef", "sig": "garbage",
    }
    ml.on_heartbeat(forged)

    assert ml.role == role_before
    assert ml.master_id == master_before
    assert ml.term == term_before


def test_unsigned_heartbeat_still_processed(tmp_path):
    """A heartbeat without a 'sig' field (the pure-logic path) is processed
    normally — backward compat is preserved for callers that never sign."""
    t = [1000.0]
    clock = lambda: t[0]
    ml = MasterLink(
        "aa", 100, lambda: [], lambda msg: None,
        TermStore(tmp_path / "term_unsigned"), clock, election_timeout=15,
    )

    ml.on_heartbeat({"term": 1, "master_id": "bb", "priority": 10, "ts": 1.0})

    assert ml.role == Role.SATELLITE
    assert ml.master_id == "bb"
    assert ml.term == 1


def test_peers_from_mesh_defensive():
    """peers_from_mesh() is a thin, defensive adapter: a well-formed stub
    yields candidates; unknown/malformed shapes degrade to []."""
    mesh_state = {
        "peers": [
            {"public_key": "pk-a", "priority": 50},
            {"public_key": "pk-b"},  # no priority -> default 100
            {"garbage": True},        # no usable key -> skipped
        ]
    }
    peers = peers_from_mesh(mesh_state)
    assert len(peers) == 2
    assert all("node_id_hex" in p and "priority" in p for p in peers)
    assert {p["priority"] for p in peers} == {50, 100}

    assert peers_from_mesh({}) == []
    assert peers_from_mesh(None) == []
    assert peers_from_mesh("not-a-dict") == []


def test_request_promotion_self_wins(tmp_path):
    """Alone (no peers), request_promotion() bumps the term, wins its own
    election, and becomes MASTER while emitting a heartbeat."""
    sends = []
    ml = MasterLink(
        "aa", 100, lambda: [], sends.append,
        TermStore(tmp_path / "term_promote_alone"), election_timeout=15,
    )
    initial_term = ml.term

    result = ml.request_promotion()

    assert result == {"promoted": True, "term": ml.term, "master": "aa", "role": "master"}
    assert ml.term == initial_term + 1
    assert ml.role == Role.MASTER
    assert ml.master_id == "aa"
    assert len(sends) == 1  # the promotion heartbeat


def test_request_promotion_loses_to_higher_priority(tmp_path):
    """A peer with a lower priority value wins the election; we step down to
    CANDIDATE, but the term is still bumped (monotonic election attempt)."""
    ml = MasterLink(
        "aa", 100, lambda: [{"node_id_hex": "bb", "priority": 1}], lambda msg: None,
        TermStore(tmp_path / "term_promote_lose"), election_timeout=15,
    )
    initial_term = ml.term

    result = ml.request_promotion()

    assert result == {"promoted": False, "term": ml.term, "master": ml.master_id, "role": "candidate"}
    assert ml.term == initial_term + 1
    assert ml.role == Role.CANDIDATE


# -- Real UDP transport + tick loop (integration) ---------------------------


def _crypto_seams(monkeypatch):
    """Trivial always-true sign/verify seam, same pattern as test_dht.py's
    _crypto_identity — this test targets transport wiring, not crypto."""
    monkeypatch.setattr(dht, "_sign_sig", lambda body: "sig")
    monkeypatch.setattr(dht, "_verify_sig", lambda body, sig, pub: True)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_udp_transport_propagates_master_via_real_sockets(monkeypatch, tmp_path):
    """Two MasterLinks talk over real loopback UDP sockets (ephemeral ports).
    The lower-priority node ticks itself into MASTER and broadcasts signed
    heartbeats; the other must adopt it as master within a short bounded wait."""
    _crypto_seams(monkeypatch)

    t = [1000.0]
    clock = lambda: t[0]

    ml_master = MasterLink(
        "aa", 10, lambda: [], lambda msg: None,
        TermStore(tmp_path / "term_udp_a"), clock,
        election_timeout=15, id_pubkey="pub-aa",
    )
    ml_sat = MasterLink(
        "bb", 100, lambda: [], lambda msg: None,
        TermStore(tmp_path / "term_udp_b"), clock,
        election_timeout=15, id_pubkey="pub-bb",
    )

    try:
        await ml_master.start(host="127.0.0.1", port=0)
        await ml_sat.start(host="127.0.0.1", port=0)

        master_port = ml_master._transport.get_extra_info("socket").getsockname()[1]
        sat_port = ml_sat._transport.get_extra_info("socket").getsockname()[1]
        ml_master._peer_addrs = [("127.0.0.1", sat_port)]
        ml_sat._peer_addrs = [("127.0.0.1", master_port)]

        # Force ml_master straight into MASTER role and let it broadcast.
        ml_master.role = Role.MASTER
        ml_master._terms.bump()
        ml_master.master_id = "aa"

        ml_master.start_ticking()

        deadline = asyncio.get_event_loop().time() + 5.0
        while ml_sat.master_id != "aa" and asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.05)

        assert ml_sat.master_id == "aa"
        assert ml_sat.role == Role.SATELLITE
    finally:
        await ml_master.stop()
        await ml_sat.stop()
