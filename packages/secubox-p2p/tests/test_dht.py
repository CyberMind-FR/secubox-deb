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
    a = canonical_record("did:x", "ii", "aa", "10.10.0.5:51823", 100)
    b = canonical_record("did:x", "ii", "aa", "10.10.0.5:51823", 100)
    assert a == b and b"did" in a and a == json.dumps(
        {"did":"did:x","endpoint":"10.10.0.5:51823","id_pubkey":"ii","ts":100,"wg_pubkey":"aa"},
        sort_keys=True, separators=(",", ":")).encode()


def test_verify_rejects_tampered(monkeypatch):
    """verify_record checks signature and DID validity."""
    import api.dht as dht
    from api.dht import canonical_record, verify_record

    monkeypatch.setattr(dht, "_did_from_pubkey", lambda hexstr: "did:x")

    rec = {"did":"did:x","id_pubkey":"ii","wg_pubkey":"aa","endpoint":"10.10.0.5:51823","ts":100,"sig":"deadbeef"}
    # verify_fn returns True only for the exact canonical bytes:
    monkeypatch.setattr(dht, "_verify_sig",
        lambda body, sig, pub: sig == "deadbeef" and body == canonical_record("did:x","ii","aa","10.10.0.5:51823",100))
    assert verify_record(rec) is True

    rec2 = dict(rec, endpoint="10.10.0.9:51823")   # tamper
    assert verify_record(rec2) is False

    rec3 = dict(rec); rec3.pop("sig")              # unsigned
    assert verify_record(rec3) is False


def test_real_ed25519_sign_and_verify_roundtrip(monkeypatch):
    """End-to-end with the REAL cryptography Ed25519 seams (no monkeypatch of
    _sign_sig/_verify_sig/_did_from_pubkey): sign a record with a real key,
    verify it, then show tampering and identity-mismatch both fail closed."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    import api.annuaire_client as annuaire_client
    from api.dht import sign_record, verify_record

    priv_key = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_hex = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    did = annuaire_client.did_from_pubkey_hex(pub_hex)

    monkeypatch.setattr(annuaire_client, "node_identity", lambda *a, **kw: (did, priv_hex))

    rec = sign_record(did, pub_hex, "wg-pubkey-hex", "10.10.0.5:51823", 100)
    assert verify_record(rec) is True

    tampered = dict(rec, endpoint="10.10.0.9:51823")
    assert verify_record(tampered) is False

    other_pub_hex = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()
    wrong_identity = dict(rec, id_pubkey=other_pub_hex)   # did no longer matches id_pubkey
    assert verify_record(wrong_identity) is False


def test_real_ed25519_verify_rejects_garbage_signature():
    """A malformed/garbage sig must fail closed, not raise."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from api.dht import verify_record
    import api.annuaire_client as annuaire_client

    pub_hex = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()
    did = annuaire_client.did_from_pubkey_hex(pub_hex)
    rec = {"did": did, "id_pubkey": pub_hex, "wg_pubkey": "wg", "endpoint": "10.10.0.5:51823",
           "ts": 100, "sig": "deadbeef"}   # too short to be a valid 64-byte Ed25519 sig
    assert verify_record(rec) is False


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
    return DHTNetwork("did:self","ii","aa","10.10.0.1:51823", send_fn=lambda d,a: sent.append((d,a)))


def test_ping_gets_pong(monkeypatch):
    sent=[]; net=_net(monkeypatch, sent)
    sender={"node_id_hex": node_id_for("peer").hex(),"did":"did:peer","endpoint":"10.10.0.2:51823"}
    net.handle_message(encode_msg(msg_ping("r1", sender)), ("10.10.0.2",51823))
    assert sent and decode_msg(sent[0][0])["t"]=="pong" and decode_msg(sent[0][0])["rpc_id"]=="r1"


def test_store_rejects_unverified(monkeypatch):
    sent=[]; net=_net(monkeypatch, sent, verified=False)
    ok = net.local_store_put("aa"*20, {"did":"did:peer","id_pubkey":"ii","wg_pubkey":"bb","endpoint":"10.10.0.2:51823","ts":1,"sig":"x"})
    assert ok is False and "aa"*20 not in net.store


def test_store_ttl_expiry(monkeypatch):
    t=[1000.0]; sent=[]
    monkeypatch.setattr(dht,"_did_from_pubkey",lambda h:"did:peer")
    monkeypatch.setattr(dht,"_verify_sig",lambda b,s,p:True)
    monkeypatch.setattr(dht,"_sign_sig",lambda b:"sig")
    net=DHTNetwork("did:self","ii","aa","10.10.0.1:51823",send_fn=lambda d,a:sent.append((d,a)),clock=lambda:t[0])
    key="bb"*20
    assert net.local_store_put(key, {"did":"did:peer","id_pubkey":"ii","wg_pubkey":"cc","endpoint":"10.10.0.2:51823","ts":1,"sig":"s"})
    assert net.local_store_get(key) is not None
    t[0]+=dht.DHT_TTL+1
    assert net.local_store_get(key) is None


# Task 7: iterative lookup (find_node/find_value), find_peer, announce, _rpc

import asyncio
from api.dht import DHTNode


def _ep(endpoint: str) -> tuple:
    host, port = endpoint.rsplit(":", 1)
    return (host, int(port))


def _make_send_fn(nets: dict, own_endpoint: str, counts: dict | None = None):
    """In-process UDP router: delivers datagrams via call_soon (never inline),
    so awaited RPC futures resolve on a later loop turn, not by re-entrance."""
    own_addr = _ep(own_endpoint)

    def send_fn(data: bytes, addr):
        dest = nets.get(f"{addr[0]}:{addr[1]}")
        if dest is None:
            return
        if counts is not None:
            msg = decode_msg(data)
            if msg is not None and msg.get("t") in ("find_node", "find_value"):
                counts[f"{addr[0]}:{addr[1]}"] = counts.get(f"{addr[0]}:{addr[1]}", 0) + 1
        asyncio.get_event_loop().call_soon(dest.handle_message, data, own_addr)

    return send_fn


def _crypto_identity(monkeypatch):
    """Make verify_record trivially true: wg_pubkey == did, sig checking is a no-op."""
    monkeypatch.setattr(dht, "_did_from_pubkey", lambda pub_hex: pub_hex)
    monkeypatch.setattr(dht, "_verify_sig", lambda body, sig, pub: True)
    monkeypatch.setattr(dht, "_sign_sig", lambda body: "sig")


@pytest.mark.asyncio
async def test_find_peer_resolves_indirect_node_via_bootstrap(monkeypatch):
    """A only knows B; B knows C; C bootstraps off B. C announces its signed
    record; A.find_peer(C.did) must resolve it despite never knowing C directly."""
    _crypto_identity(monkeypatch)

    nets: dict = {}
    a_ep, b_ep, c_ep = "10.10.0.1:51823", "10.10.0.2:51823", "10.10.0.3:51823"

    A = DHTNetwork("did:A", "did:A", "wg:A", a_ep, send_fn=_make_send_fn(nets, a_ep))
    B = DHTNetwork("did:B", "did:B", "wg:B", b_ep, send_fn=_make_send_fn(nets, b_ep))
    C = DHTNetwork("did:C", "did:C", "wg:C", c_ep, send_fn=_make_send_fn(nets, c_ep))
    nets[a_ep] = A; nets[b_ep] = B; nets[c_ep] = C

    A.routing.insert(DHTNode(B.self_id, B.did, _ep(b_ep)))
    B.routing.insert(DHTNode(C.self_id, C.did, _ep(c_ep)))
    C.routing.insert(DHTNode(B.self_id, B.did, _ep(b_ep)))  # C's bootstrap contact

    await C.announce()

    counts: dict = {}
    for net, ep in ((A, a_ep), (B, b_ep), (C, c_ep)):
        net.send_fn = _make_send_fn(nets, ep, counts)

    result = await A.find_peer(C.did)

    assert result is not None
    assert result["did"] == C.did
    assert result["endpoint"] == c_ep
    assert dht.verify_record(result) is True
    # A never had C directly in its routing table before the lookup:
    assert all(v <= 1 for v in counts.values())  # no node queried twice
    assert counts.get(b_ep, 0) >= 1


@pytest.mark.asyncio
async def test_iterative_find_dedup_across_merged_contacts(monkeypatch):
    """A knows B and D; both B and D know E. E is introduced into A's shortlist
    twice (once via B's reply, once via D's), but must be queried only once."""
    _crypto_identity(monkeypatch)

    nets: dict = {}
    a_ep, b_ep, d_ep, e_ep = (
        "10.10.0.1:51823", "10.10.0.2:51823", "10.10.0.4:51823", "10.10.0.5:51823",
    )
    counts: dict = {}

    A = DHTNetwork("did:A", "did:A", "wg:A", a_ep, send_fn=_make_send_fn(nets, a_ep, counts))
    B = DHTNetwork("did:B", "did:B", "wg:B", b_ep, send_fn=_make_send_fn(nets, b_ep, counts))
    D = DHTNetwork("did:D", "did:D", "wg:D", d_ep, send_fn=_make_send_fn(nets, d_ep, counts))
    E = DHTNetwork("did:E", "did:E", "wg:E", e_ep, send_fn=_make_send_fn(nets, e_ep, counts))
    nets[a_ep] = A; nets[b_ep] = B; nets[d_ep] = D; nets[e_ep] = E

    A.routing.insert(DHTNode(B.self_id, B.did, _ep(b_ep)))
    A.routing.insert(DHTNode(D.self_id, D.did, _ep(d_ep)))
    B.routing.insert(DHTNode(E.self_id, E.did, _ep(e_ep)))
    D.routing.insert(DHTNode(E.self_id, E.did, _ep(e_ep)))

    target = E.self_id  # guarantees E strictly improves distance once merged
    result = await A.iterative_find(target, "node")

    assert any(n.node_id == E.self_id for n in result)
    assert counts.get(e_ep, 0) == 1     # merged twice (via B and via D), queried once
    assert counts.get(b_ep, 0) == 1
    assert counts.get(d_ep, 0) == 1


@pytest.mark.asyncio
async def test_find_peer_survives_malformed_contact_in_reply(monkeypatch):
    """B replies to A's find_value with a shortlist containing one MALFORMED
    contact (bad hex node_id_hex, bogus did, endpoint with no port) alongside
    one good contact (C) that leads to the target. A single bad peer/contact
    must never crash the lookup — find_peer must still resolve C's record."""
    _crypto_identity(monkeypatch)

    nets: dict = {}
    a_ep, b_ep, c_ep = "10.10.0.1:51823", "10.10.0.2:51823", "10.10.0.3:51823"

    A = DHTNetwork("did:A", "did:A", "wg:A", a_ep, send_fn=_make_send_fn(nets, a_ep))
    B = DHTNetwork("did:B", "did:B", "wg:B", b_ep, send_fn=_make_send_fn(nets, b_ep))
    C = DHTNetwork("did:C", "did:C", "wg:C", c_ep, send_fn=_make_send_fn(nets, c_ep))
    nets[a_ep] = A; nets[b_ep] = B; nets[c_ep] = C

    A.routing.insert(DHTNode(B.self_id, B.did, _ep(b_ep)))
    B.routing.insert(DHTNode(C.self_id, C.did, _ep(c_ep)))

    # C holds its own signed record locally (no announce/push — this keeps
    # B's find_value reply on the "nodes" branch, below, so we can poison it).
    record = dht.sign_record(C.did, C.id_pubkey, C.wg_pubkey, C.endpoint, int(C._clock()))
    C.local_store_put(C.self_id.hex(), record)

    # Wrap B's outgoing reply: whenever it would send a "nodes" message,
    # splice a malformed contact in ahead of the real (good) contacts.
    real_reply = B._reply

    def poisoned_reply(msg, addr):
        if msg.get("t") == "nodes":
            msg = dict(msg)
            msg["nodes"] = [
                {"node_id_hex": "zz", "did": "did:bad", "endpoint": "noport"},
                *msg["nodes"],
            ]
        real_reply(msg, addr)

    B._reply = poisoned_reply

    result = await A.find_peer(C.did)

    assert result is not None
    assert result["did"] == C.did
    assert result["endpoint"] == c_ep
    assert dht.verify_record(result) is True


# Task 8b: UDP transport + routing persistence + bootstrap


def test_save_and_load_routing_roundtrip(tmp_path):
    """save_routing writes 0600 JSON; a fresh network's load_routing reinserts
    the same contacts and reports how many were inserted."""
    net = DHTNetwork("did:self", "ii", "aa", "10.10.0.1:51823")
    b = DHTNode(node_id_for("did:b"), "did:b", ("10.10.0.2", 51823))
    c = DHTNode(node_id_for("did:c"), "did:c", ("10.10.0.3", 51823))
    net.routing.insert(b)
    net.routing.insert(c)

    path = tmp_path / "r.json"
    net.save_routing(path)

    assert path.exists()
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600

    net2 = DHTNetwork("did:other", "ii2", "aa2", "10.10.0.9:51823")
    count = net2.load_routing(path)

    assert count == 2
    loaded_ids = {n.node_id for n in net2.routing.all_nodes()}
    assert b.node_id in loaded_ids and c.node_id in loaded_ids


def test_load_routing_missing_file_returns_zero(tmp_path):
    net = DHTNetwork("did:self", "ii", "aa", "10.10.0.1:51823")
    count = net.load_routing(tmp_path / "does-not-exist.json")
    assert count == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_udp_bootstrap_and_find_peer(monkeypatch):
    """End-to-end over real loopback UDP sockets (ephemeral ports): B announces
    its signed record; A bootstraps off B's address alone (no identity known in
    advance) and must resolve B's record via find_peer. This targets the
    transport wiring, not the crypto — so the sign/verify seams are
    monkeypatched to a trivial always-true scheme, same pattern as the other
    Task 7 in-process tests."""
    _crypto_identity(monkeypatch)

    A = DHTNetwork("did:A", "did:A", "wg:A", "127.0.0.1:0")
    B = DHTNetwork("did:B", "did:B", "wg:B", "127.0.0.1:0")

    try:
        await A.start(host="127.0.0.1", port=0)
        await B.start(host="127.0.0.1", port=0)

        a_port = A._transport.get_extra_info("socket").getsockname()[1]
        b_port = B._transport.get_extra_info("socket").getsockname()[1]
        A.endpoint = f"127.0.0.1:{a_port}"
        B.endpoint = f"127.0.0.1:{b_port}"

        await B.announce()
        inserted = await A.bootstrap(seeds=[B.endpoint])

        assert inserted >= 1
        result = await A.find_peer(B.did)
        assert result is not None
        assert result["did"] == B.did
        assert result["endpoint"] == B.endpoint
    finally:
        await A.stop()
        await B.stop()
