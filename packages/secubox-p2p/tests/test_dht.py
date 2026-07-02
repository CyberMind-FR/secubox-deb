# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import hashlib
import pytest
from api.dht import node_id_for, xor_distance, KAD_K, KAD_ID_BITS, DHT_PORT, DHTNode, DHTBucket


def test_node_id_is_sha1_of_did():
    did = "did:key:zabc"
    assert node_id_for(did) == hashlib.sha1(did.encode()).digest()
    assert len(node_id_for(did)) == KAD_ID_BITS // 8


def test_xor_distance_symmetry_and_zero():
    a = node_id_for("a"); b = node_id_for("b")
    assert xor_distance(a, b) == xor_distance(b, a)
    assert xor_distance(a, a) == 0
    assert xor_distance(a, b) > 0


def test_constants():
    assert KAD_K == 20 and KAD_ID_BITS == 160 and DHT_PORT == 51823


# Task 2: DHTNode and DHTBucket

def _n(name, port=51823):
    """Create a test DHTNode with given name (used as did identifier)."""
    return DHTNode(node_id_for(name), f"did:{name}", ("10.10.0.5", port))


def test_bucket_add_and_refresh_moves_to_tail():
    """Adding a node twice should move it to the tail (most-recent)."""
    b = DHTBucket(k=2)
    a, c = _n("a"), _n("c")
    assert b.add(a) and b.add(c)
    assert [x.did for x in b.nodes] == ["did:a", "did:c"]
    assert b.add(a)                      # refresh existing
    assert [x.did for x in b.nodes] == ["did:c", "did:a"]   # a moved to tail (most-recent)


def test_bucket_full_rejects_new_and_reports_oldest():
    """Adding to a full bucket should return False; oldest() should return the head."""
    b = DHTBucket(k=1)
    a, c = _n("a"), _n("c")
    assert b.add(a)
    assert b.add(c) is False             # full
    assert b.oldest().did == "did:a"
