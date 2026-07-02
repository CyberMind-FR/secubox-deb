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


# Task 3: RoutingTable

def test_closest_orders_by_xor_distance():
    from api.dht import RoutingTable
    me = node_id_for("me")
    rt = RoutingTable(me)
    for name in ("a", "b", "c", "d", "e"):
        nid = node_id_for(name)
        rt.insert(DHTNode(nid, f"did:{name}", ("10.10.0.9", 51823)))
    target = node_id_for("c")
    got = rt.closest(target, count=3)
    assert len(got) == 3
    dists = [xor_distance(n.node_id, target) for n in got]
    assert dists == sorted(dists)        # nearest first
    assert got[0].did == "did:c"         # exact target is nearest


def test_insert_ignores_self():
    from api.dht import RoutingTable
    me = node_id_for("me")
    rt = RoutingTable(me)
    assert rt.insert(DHTNode(me, "did:me", ("10.10.0.1", 51823))) is False


# Task 4: Signed reachability records

def test_canonical_is_stable_and_sorted():
    """canonical_record produces deterministic sorted JSON."""
    import json
    from api.dht import canonical_record
    a = canonical_record("did:x", "aa", "10.10.0.5:51823", 100)
    b = canonical_record("did:x", "aa", "10.10.0.5:51823", 100)
    assert a == b and b"did" in a and a == json.dumps(
        {"did":"did:x","endpoint":"10.10.0.5:51823","ts":100,"wg_pubkey":"aa"},
        sort_keys=True, separators=(",", ":")).encode()


def test_verify_rejects_tampered(monkeypatch):
    """verify_record checks signature and DID validity."""
    import api.dht as dht
    from api.dht import canonical_record, verify_record

    monkeypatch.setattr(dht, "_did_from_pubkey", lambda hexstr: "did:x")

    rec = {"did":"did:x","wg_pubkey":"aa","endpoint":"10.10.0.5:51823","ts":100,"sig":"deadbeef"}
    # verify_fn returns True only for the exact canonical bytes:
    monkeypatch.setattr(dht, "_verify_sig",
        lambda body, sig, pub: sig == "deadbeef" and body == canonical_record("did:x","aa","10.10.0.5:51823",100))
    assert verify_record(rec) is True

    rec2 = dict(rec, endpoint="10.10.0.9:51823")   # tamper
    assert verify_record(rec2) is False

    rec3 = dict(rec); rec3.pop("sig")              # unsigned
    assert verify_record(rec3) is False


# Task 5: JSON UDP RPC codec + datagram hardening

def test_roundtrip():
    from api.dht import encode_msg, decode_msg
    m = {"t":"ping","rpc_id":"ab","sender":{"node_id_hex":"00","did":"did:a","endpoint":"10.10.0.5:51823"}}
    assert decode_msg(encode_msg(m)) == m


def test_decode_rejects_malformed_and_oversized():
    from api.dht import encode_msg, decode_msg, MAX_DGRAM
    assert decode_msg(b"not json") is None
    assert decode_msg(b"[1,2,3]") is None            # not a dict
    assert decode_msg(b"{}") is None                  # missing required 't'
    assert decode_msg(b"x" * (MAX_DGRAM + 1)) is None # oversized


# Task 6: DHTNetwork core — value store with TTL + handle_message (transport-injected)

import api.dht as dht
from api.dht import DHTNetwork, node_id_for, encode_msg, decode_msg, msg_ping


def _net(monkeypatch, sent, verified=True):
    monkeypatch.setattr(dht, "_did_from_pubkey", lambda h: "did:self")
    monkeypatch.setattr(dht, "_verify_sig", lambda b,s,p: verified)
    monkeypatch.setattr(dht, "_sign_sig", lambda b: "sig")
    return DHTNetwork("did:self","aa","10.10.0.1:51823", send_fn=lambda d,a: sent.append((d,a)))


def test_ping_gets_pong(monkeypatch):
    sent=[]; net=_net(monkeypatch, sent)
    sender={"node_id_hex": node_id_for("peer").hex(),"did":"did:peer","endpoint":"10.10.0.2:51823"}
    net.handle_message(encode_msg(msg_ping("r1", sender)), ("10.10.0.2",51823))
    assert sent and decode_msg(sent[0][0])["t"]=="pong" and decode_msg(sent[0][0])["rpc_id"]=="r1"


def test_store_rejects_unverified(monkeypatch):
    sent=[]; net=_net(monkeypatch, sent, verified=False)
    ok = net.local_store_put("aa"*20, {"did":"did:peer","wg_pubkey":"bb","endpoint":"10.10.0.2:51823","ts":1,"sig":"x"})
    assert ok is False and "aa"*20 not in net.store


def test_store_ttl_expiry(monkeypatch):
    t=[1000.0]; sent=[]
    monkeypatch.setattr(dht,"_did_from_pubkey",lambda h:"did:peer")
    monkeypatch.setattr(dht,"_verify_sig",lambda b,s,p:True)
    monkeypatch.setattr(dht,"_sign_sig",lambda b:"sig")
    net=DHTNetwork("did:self","aa","10.10.0.1:51823",send_fn=lambda d,a:sent.append((d,a)),clock=lambda:t[0])
    key="bb"*20
    assert net.local_store_put(key, {"did":"did:peer","wg_pubkey":"cc","endpoint":"10.10.0.2:51823","ts":1,"sig":"s"})
    assert net.local_store_get(key) is not None
    t[0]+=dht.DHT_TTL+1
    assert net.local_store_get(key) is None
