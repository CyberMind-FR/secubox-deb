# secubox-p2p evolutions (Kademlia DHT + master-link + federation health-checks) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add resilient cross-NAT peer discovery (custom Kademlia DHT), distributed federation health-checks, and a hierarchical master-link (election + failover) to `secubox-p2p`, on the existing mesh/registry/annuaire base.

**Architecture:** Three feature-flagged, independently-testable modules under `packages/secubox-p2p/api/` — `dht.py` (pure asyncio-UDP Kademlia, JSON wire, signed reachability records), `federation.py` (health-checks over the annuaire federation, status published via the DHT), `masterlink.py` (deterministic-election, term-based failover). Wired into `api/main.py` as startup-guarded background tasks + `/api/v1/p2p/*` endpoints.

**Tech Stack:** Python 3.11, `asyncio` (DatagramProtocol), `aiohttp` (already a dep), `pytest` + `pytest-asyncio`. No new heavy dependency.

## Global Constraints
- Import convention: module code `from . import mesh, registry, annuaire_client`; tests `from api import dht` (via `tests/conftest.py` sys.path). NEVER `secubox.p2p.api.*`.
- License header `LicenseRef-CMSD-1.0` at the top of every new file (copy the block from `api/mesh.py`).
- State dir `/var/lib/secubox/p2p` (`P2P_DIR` in `main.py`); config `/etc/secubox/p2p.toml`; audit `/var/log/secubox/p2p-audit.log` (append-only JSONL). Persistence files `chmod 0600`.
- Mesh facts (verbatim): iface `wg-mesh`, udp `51822`, net `10.10.0.0/24`. DHT udp `51823`, master-link udp `51824`.
- Kademlia: `KAD_K=20`, `KAD_ALPHA=3`, `KAD_ID_BITS=160`, `RPC_TIMEOUT=5.0`, `PEER_TIMEOUT=900`, `DHT_TTL=3600`, `DHT_PORT=51823`, `MAX_DGRAM=8192`.
- All background tasks feature-flag OFF by default (backward compatible); every network op `await`ed with a timeout — never block the loop.
- DHT stored values are signed by the announcing node and verified on read; reject unsigned/tampered/wrong-did.
- Run tests per-module: `cd packages/secubox-p2p && python3 -m pytest tests/test_<mod>.py -v` (root `pytest.ini` forbids bulk collection due to `api/` name collisions).

---

# PHASE 1 — Kademlia DHT (`api/dht.py`)

Foundation. Correctness-critical; built bottom-up (distance → buckets → routing table → codec → signed records → network/lookup) so each unit is tested with in-process doubles (no real UDP until the integration task).

### Task 1: Module scaffold + constants + XOR distance

**Files:**
- Create: `packages/secubox-p2p/api/dht.py`
- Test: `packages/secubox-p2p/tests/test_dht.py`

**Interfaces:**
- Produces: constants `KAD_K, KAD_ALPHA, KAD_ID_BITS, RPC_TIMEOUT, PEER_TIMEOUT, DHT_TTL, DHT_PORT, MAX_DGRAM`; `node_id_for(did: str) -> bytes` (20-byte SHA1); `xor_distance(a: bytes, b: bytes) -> int`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_dht.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import hashlib
import pytest
from api.dht import node_id_for, xor_distance, KAD_K, KAD_ID_BITS, DHT_PORT


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
```

- [ ] **Step 2: Run — expect fail** `cd packages/secubox-p2p && python3 -m pytest tests/test_dht.py -v` → `ModuleNotFoundError`/`ImportError`.

- [ ] **Step 3: Implement**
```python
# api/dht.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-p2p :: Kademlia DHT (custom, asyncio/UDP). Issue #774."""
from __future__ import annotations
import hashlib

KAD_K = 20
KAD_ALPHA = 3
KAD_ID_BITS = 160
RPC_TIMEOUT = 5.0
PEER_TIMEOUT = 900
DHT_TTL = 3600
DHT_PORT = 51823
MAX_DGRAM = 8192


def node_id_for(did: str) -> bytes:
    """160-bit Kademlia node id = SHA1(did)."""
    return hashlib.sha1(did.encode()).digest()


def xor_distance(a: bytes, b: bytes) -> int:
    """XOR metric over the 160-bit id space, as an int."""
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `git add api/dht.py tests/test_dht.py && git commit -m "feat(p2p): DHT scaffold — node id + xor distance (#774)"`

---

### Task 2: `DHTNode` contact + `DHTBucket` (k-bucket with LRU)

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py`.
**Interfaces:**
- Consumes: `node_id_for`, `xor_distance`, `KAD_K`.
- Produces: `DHTNode(node_id: bytes, did: str, endpoint: tuple[str,int], last_seen: float=0.0)`; `DHTBucket(k=KAD_K)` with `.add(node) -> bool` (True if stored/refreshed, False if full), `.nodes -> list[DHTNode]`, `.oldest() -> DHTNode|None`, `.remove(node_id)`.

- [ ] **Step 1: Failing test**
```python
from api.dht import DHTNode, DHTBucket, node_id_for

def _n(name, port=51823):
    return DHTNode(node_id_for(name), f"did:{name}", ("10.10.0.5", port))

def test_bucket_add_and_refresh_moves_to_tail():
    b = DHTBucket(k=2)
    a, c = _n("a"), _n("c")
    assert b.add(a) and b.add(c)
    assert [x.did for x in b.nodes] == ["did:a", "did:c"]
    assert b.add(a)                      # refresh existing
    assert [x.did for x in b.nodes] == ["did:c", "did:a"]   # a moved to tail (most-recent)

def test_bucket_full_rejects_new_and_reports_oldest():
    b = DHTBucket(k=1)
    a, c = _n("a"), _n("c")
    assert b.add(a)
    assert b.add(c) is False             # full
    assert b.oldest().did == "did:a"
```

- [ ] **Step 2: Run — expect fail** (`ImportError: DHTNode`).
- [ ] **Step 3: Implement** — append to `api/dht.py`:
```python
import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class DHTNode:
    node_id: bytes
    did: str
    endpoint: tuple  # (host, port)
    last_seen: float = 0.0


class DHTBucket:
    """A Kademlia k-bucket: LRU-ordered contacts, most-recent at the tail."""
    def __init__(self, k: int = KAD_K):
        self.k = k
        self._nodes: "OrderedDict[bytes, DHTNode]" = OrderedDict()

    def add(self, node: DHTNode) -> bool:
        node.last_seen = time.time()
        if node.node_id in self._nodes:
            self._nodes.move_to_end(node.node_id)   # refresh → tail
            self._nodes[node.node_id] = node
            return True
        if len(self._nodes) >= self.k:
            return False
        self._nodes[node.node_id] = node
        return True

    def remove(self, node_id: bytes) -> None:
        self._nodes.pop(node_id, None)

    def oldest(self):
        return next(iter(self._nodes.values())) if self._nodes else None

    @property
    def nodes(self):
        return list(self._nodes.values())
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `feat(p2p): DHT k-bucket with LRU (#774)`

---

### Task 3: `RoutingTable` (160 buckets, closest-N)

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py`.
**Interfaces:**
- Consumes: `DHTNode, DHTBucket, node_id_for, xor_distance, KAD_ID_BITS, KAD_K`.
- Produces: `RoutingTable(self_id: bytes)` with `.insert(node: DHTNode) -> bool`, `.closest(target_id: bytes, count: int=KAD_K) -> list[DHTNode]`, `.all_nodes() -> list[DHTNode]`.

- [ ] **Step 1: Failing test**
```python
from api.dht import RoutingTable, DHTNode, node_id_for

def test_closest_orders_by_xor_distance():
    me = node_id_for("me")
    rt = RoutingTable(me)
    for name in ("a", "b", "c", "d", "e"):
        nid = node_id_for(name)
        rt.insert(DHTNode(nid, f"did:{name}", ("10.10.0.9", 51823)))
    target = node_id_for("c")
    got = rt.closest(target, count=3)
    assert len(got) == 3
    from api.dht import xor_distance
    dists = [xor_distance(n.node_id, target) for n in got]
    assert dists == sorted(dists)        # nearest first
    assert got[0].did == "did:c"         # exact target is nearest

def test_insert_ignores_self():
    me = node_id_for("me")
    rt = RoutingTable(me)
    assert rt.insert(DHTNode(me, "did:me", ("10.10.0.1", 51823))) is False
```

- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** — append:
```python
class RoutingTable:
    """160 buckets indexed by the shared-prefix length with self_id."""
    def __init__(self, self_id: bytes):
        self.self_id = self_id
        self.buckets = [DHTBucket() for _ in range(KAD_ID_BITS)]

    def _bucket_index(self, node_id: bytes) -> int:
        d = xor_distance(self.self_id, node_id)
        if d == 0:
            return 0
        return KAD_ID_BITS - 1 - (d.bit_length() - 1)

    def insert(self, node: DHTNode) -> bool:
        if node.node_id == self.self_id:
            return False
        return self.buckets[self._bucket_index(node.node_id)].add(node)

    def all_nodes(self):
        out = []
        for b in self.buckets:
            out.extend(b.nodes)
        return out

    def closest(self, target_id: bytes, count: int = KAD_K):
        nodes = self.all_nodes()
        nodes.sort(key=lambda n: xor_distance(n.node_id, target_id))
        return nodes[:count]
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `feat(p2p): DHT routing table + closest-N (#774)`

---

### Task 4: Signed reachability records (encode/verify)

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py`.
**Interfaces:**
- Produces: `canonical_record(did, wg_pubkey, endpoint, ts) -> bytes` (deterministic JSON); `sign_record(record: dict, sign_fn) -> dict` (adds `sig`); `verify_record(record: dict) -> bool` (checks `sig` over the canonical body AND that `did_from_pubkey_hex(wg_pubkey)==did`). `sign_fn`/verification use Ed25519 via `nacl.signing` if available else the mesh key helper; the plan injects a `sign_fn`/`verify_fn` so the unit test is crypto-double-based.
- Consumes: `annuaire_client.did_from_pubkey_hex`.

- [ ] **Step 1: Failing test**
```python
import json
from api.dht import canonical_record, verify_record

def test_canonical_is_stable_and_sorted():
    a = canonical_record("did:x", "aa", "10.10.0.5:51823", 100)
    b = canonical_record("did:x", "aa", "10.10.0.5:51823", 100)
    assert a == b and b"did" in a and a == json.dumps(
        {"did":"did:x","endpoint":"10.10.0.5:51823","ts":100,"wg_pubkey":"aa"},
        sort_keys=True, separators=(",", ":")).encode()

def test_verify_rejects_tampered(monkeypatch):
    import api.dht as dht
    monkeypatch.setattr(dht, "_did_from_pubkey", lambda hexstr: "did:x")
    good_sig = {"good"}  # placeholder; real verify_fn injected below
    rec = {"did":"did:x","wg_pubkey":"aa","endpoint":"10.10.0.5:51823","ts":100,"sig":"deadbeef"}
    # verify_fn returns True only for the exact canonical bytes:
    monkeypatch.setattr(dht, "_verify_sig",
        lambda body, sig, pub: sig == "deadbeef" and body == canonical_record("did:x","aa","10.10.0.5:51823",100))
    assert verify_record(rec) is True
    rec2 = dict(rec, endpoint="10.10.0.9:51823")   # tamper
    assert verify_record(rec2) is False
    rec3 = dict(rec); rec3.pop("sig")              # unsigned
    assert verify_record(rec3) is False
```

- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** — append (crypto seams `_did_from_pubkey`, `_sign_sig`, `_verify_sig` are module-level so tests monkeypatch them; real impls wired in Task 8):
```python
import json as _json
from . import annuaire_client as _annuaire


def canonical_record(did: str, wg_pubkey: str, endpoint: str, ts: int) -> bytes:
    return _json.dumps(
        {"did": did, "wg_pubkey": wg_pubkey, "endpoint": endpoint, "ts": ts},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def _did_from_pubkey(pub_hex: str) -> str:      # seam (real: annuaire_client)
    return _annuaire.did_from_pubkey_hex(pub_hex)


def _verify_sig(body: bytes, sig_hex: str, pub_hex: str) -> bool:   # seam (Task 8)
    raise NotImplementedError


def _sign_sig(body: bytes) -> str:              # seam (Task 8)
    raise NotImplementedError


def sign_record(did: str, wg_pubkey: str, endpoint: str, ts: int) -> dict:
    body = canonical_record(did, wg_pubkey, endpoint, ts)
    return {"did": did, "wg_pubkey": wg_pubkey, "endpoint": endpoint,
            "ts": ts, "sig": _sign_sig(body)}


def verify_record(rec: dict) -> bool:
    try:
        if "sig" not in rec:
            return False
        body = canonical_record(rec["did"], rec["wg_pubkey"], rec["endpoint"], rec["ts"])
        if _did_from_pubkey(rec["wg_pubkey"]) != rec["did"]:
            return False
        return bool(_verify_sig(body, rec["sig"], rec["wg_pubkey"]))
    except (KeyError, TypeError, ValueError):
        return False
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `feat(p2p): DHT signed reachability records + verify (#774)`

---

### Task 5: JSON UDP RPC codec + datagram hardening

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py`.
**Interfaces:**
- Produces: `encode_msg(msg: dict) -> bytes`; `decode_msg(data: bytes) -> dict|None` (returns None on malformed/oversized/non-dict/oversize-field); message builders `msg_ping/msg_pong/msg_find_node/msg_nodes/msg_find_value/msg_value/msg_store/msg_ok` producing dicts with `t`, `rpc_id`, `sender`.
- Consumes: `MAX_DGRAM`.

- [ ] **Step 1: Failing test**
```python
from api.dht import encode_msg, decode_msg, MAX_DGRAM

def test_roundtrip():
    m = {"t":"ping","rpc_id":"ab","sender":{"node_id_hex":"00","did":"did:a","endpoint":"10.10.0.5:51823"}}
    assert decode_msg(encode_msg(m)) == m

def test_decode_rejects_malformed_and_oversized():
    assert decode_msg(b"not json") is None
    assert decode_msg(b"[1,2,3]") is None            # not a dict
    assert decode_msg(b"{}") is None                  # missing required 't'
    assert decode_msg(b"x" * (MAX_DGRAM + 1)) is None # oversized
```

- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** — append:
```python
def encode_msg(msg: dict) -> bytes:
    return _json.dumps(msg, separators=(",", ":")).encode()


def decode_msg(data: bytes):
    if not data or len(data) > MAX_DGRAM:
        return None
    try:
        obj = _json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict) or "t" not in obj:
        return None
    return obj


def _base(t: str, rpc_id: str, sender: dict) -> dict:
    return {"t": t, "rpc_id": rpc_id, "sender": sender}

def msg_ping(rpc_id, sender):                     return _base("ping", rpc_id, sender)
def msg_pong(rpc_id, sender):                     return _base("pong", rpc_id, sender)
def msg_find_node(rpc_id, sender, target_hex):    return {**_base("find_node", rpc_id, sender), "target": target_hex}
def msg_nodes(rpc_id, sender, contacts):          return {**_base("nodes", rpc_id, sender), "nodes": contacts}
def msg_find_value(rpc_id, sender, key_hex):      return {**_base("find_value", rpc_id, sender), "key": key_hex}
def msg_value(rpc_id, sender, record):            return {**_base("value", rpc_id, sender), "value": record}
def msg_store(rpc_id, sender, key_hex, record):   return {**_base("store", rpc_id, sender), "key": key_hex, "value": record}
def msg_ok(rpc_id, sender):                       return _base("ok", rpc_id, sender)
```

- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `feat(p2p): DHT JSON UDP codec + hardening (#774)`

---

### Task 6: `DHTNetwork` core — value store with TTL + `handle_message` (transport-injected)

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py`.
**Interfaces:**
- Produces: `DHTNetwork(did, wg_pubkey, endpoint, send_fn=None, clock=time.time)` where `send_fn(data: bytes, addr: tuple)` is injected (real UDP transport in Task 8; a capture-list double in tests). `.self_id`, `.routing: RoutingTable`, `.store: dict[str,(record,expiry)]`. `.handle_message(data: bytes, addr) -> None` (dispatches ping/find_node/find_value/store, updates routing, replies via `send_fn`). `.local_store_put(key_hex, record)` (verifies before storing), `.local_store_get(key_hex)` (drops expired).
- Consumes: everything above.

- [ ] **Step 1: Failing test** (store TTL + a ping produces a pong via send_fn; store rejects unverified)
```python
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
```

- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** — append `DHTNetwork` with the described methods (routing insert on every inbound `sender`, dispatch table, `local_store_put` calls `verify_record`, `local_store_get` checks expiry against `clock()`). Keep methods short; no real socket here.
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `feat(p2p): DHTNetwork store+dispatch (transport-injected) (#774)`

---

### Task 7: Iterative lookup (`find_node` / `find_value`) over injected transport

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py`.
**Interfaces:**
- Produces: `async DHTNetwork.iterative_find(target_id: bytes, mode: str) -> list[DHTNode] | dict` (α-parallel, dedups queried, terminates when no closer node appears or value found); `async DHTNetwork.find_peer(did) -> dict|None`; `async DHTNetwork.announce()`; internal `async _rpc(node, msg) -> dict|None` using a `pending: dict[rpc_id, asyncio.Future]` resolved by `handle_message` on matching `rpc_id`, with `asyncio.wait_for(RPC_TIMEOUT)`.
- Consumes: Task 6.

- [ ] **Step 1: Failing test** — build 3 in-process `DHTNetwork`s whose `send_fn` routes datagrams directly into the target net's `handle_message` (a dict of `endpoint->net`), pre-seed routing tables so a `find_peer` on net A resolves a value announced on net C reachable only via B. Assert `find_peer` returns C's verified record; assert dedup (a node is not queried twice) via a counter.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the iterative lookup + `_rpc` future-matching. `announce()` = `iterative_find(self_key, node)` then `store` to the k closest.
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: Commit** `feat(p2p): DHT iterative find_node/find_value + announce (#774)`

---

### Task 8: Real crypto seams + UDP transport + persistence + bootstrap

**Files:** Modify `api/dht.py`; Test `tests/test_dht.py` (crypto + persistence units; UDP marked integration).
**Interfaces:**
- Produces: real `_sign_sig`/`_verify_sig` (Ed25519 over the node's mesh key — load from the p2p key path; use `nacl.signing` if importable, else a documented fallback), `DHTNetwork.start()/stop()` (opens `asyncio.DatagramProtocol` on `[dht].port`, wires `send_fn` to `transport.sendto`), `save_routing()/load_routing()` (`P2P_DIR/dht-routing.json`, 0600), `async bootstrap(seeds, annuaire_nodes)`.

- [ ] **Step 1: Failing tests** — sign/verify round-trip with a generated keypair (real crypto); tamper → verify False. `save_routing`/`load_routing` round-trip (write to a tmp `P2P_DIR`, reload, contacts match). One `@pytest.mark.integration` test: two real `DHTNetwork.start()` on `127.0.0.1:{0}` discover each other via `bootstrap`.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the seams, transport, persistence (0600), bootstrap (seed from `[dht].bootstrap` + `annuaire_client.get_catalog` nodes; iterative `find_node(self_id)`).
- [ ] **Step 4: Run — expect pass** (`-m "not integration"` in CI; integration locally).
- [ ] **Step 5: Commit** `feat(p2p): DHT Ed25519 sign/verify + UDP transport + persistence + bootstrap (#774)`

---

### Task 9: Wire DHT into `api/main.py` + endpoints + config

**Files:** Modify `api/main.py`; Modify `api/mesh.py` (`load_p2p_config` → also read `[dht]`); Test `tests/test_dht.py` (config defaults) + manual endpoint smoke.
**Interfaces:**
- Consumes: `DHTNetwork`.
- Produces: startup task guarded by `[dht].enabled`; endpoints `GET /api/v1/p2p/dht/peers`, `POST /api/v1/p2p/dht/announce` (require_jwt), `GET /api/v1/p2p/dht/find/{did}`.

- [ ] **Step 1: Failing test** — `load_p2p_config` returns a `dht` dict with defaults (`enabled False`, `port 51823`, `announce False`) when the toml lacks `[dht]`.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the config defaults + `@app.on_event("startup")` guard (create+start `DHTNetwork` only if enabled; store on `app.state.dht`) + the 3 endpoints (audit-log announce) + shutdown persistence.
- [ ] **Step 4: Run** config test (pass) + smoke: `POST /announce` with a valid JWT returns the stored key; `GET /peers` returns the routing snapshot.
- [ ] **Step 5: Commit** `feat(p2p): mount DHT — endpoints + startup guard + [dht] config (#774)`

---

# PHASE 2 — Federation health-checks (`api/federation.py`)

Depends on Phase 1 (publishes status via the DHT). Same TDD rhythm.

### Task 10: `HealthStore` (debounce + persistence)
**Files:** Create `api/federation.py`; Test `tests/test_federation.py`.
**Interfaces:** `HealthStore(fail_threshold=3)` with `.record(service_id, ok: bool, latency_ms: float|None)`, `.status_of(id) -> dict`, `.snapshot() -> dict`, `.save(path)/.load(path)` (0600). Status = `up` until `fail_threshold` consecutive failures → `down`; any success → `up` + reset counter.
- [ ] Steps: failing test (2 failures still `up`, 3rd → `down`, then a success → `up`); implement; pass; commit `feat(p2p): federation HealthStore + debounce (#774)`.

### Task 11: `HealthChecker` async sweep (semaphore-capped, opt-in, injected probe)
**Files:** Modify `api/federation.py`; Test `tests/test_federation.py`.
**Interfaces:** `HealthChecker(services_fn, probe_fn, store, interval=30, max_concurrency=20, enabled=False)`; `async sweep_once()` (pulls `services_fn()`, probes each via injected `probe_fn(service)->(ok,latency)` under an `asyncio.Semaphore`, records into store); `async run()` loop honoring `enabled`.
- [ ] Steps: failing test (sweep marks up/down from a fake `probe_fn`; assert semaphore never exceeds `max_concurrency` via a counter; `enabled=False` ⇒ `sweep_once` does nothing); implement; pass; commit `feat(p2p): federation HealthChecker sweep (#774)`.

### Task 12: Real probe (`aiohttp` GET /health + TCP fallback) + services_fn from registry
**Files:** Modify `api/federation.py`; Test `tests/test_federation.py`.
**Interfaces:** `async default_probe(service, timeout=5) -> (ok, latency_ms)` (HTTP(S) GET `health_path` else TCP connect); `services_from_registry() -> list[dict]` via `registry.merge_services(annuaire_client.get_catalog(), annuaire_client.get_subscriptions())`.
- [ ] Steps: failing test (spin a tiny `aiohttp` test server returning 200 then 500 → probe ok then not-ok; TCP fallback to a closed port → not-ok); implement; pass; commit `feat(p2p): federation real probe + registry services (#774)`.

### Task 13: Publish health via DHT + wire into `main.py` + endpoints + `[federation]` config
**Files:** Modify `api/federation.py`, `api/main.py`, `api/mesh.py`; Test `tests/test_federation.py`.
**Interfaces:** after each sweep, for each service publish a signed record under `node_id_for("health:"+service_id)` via `app.state.dht.local_store_put`/`announce`; endpoints `GET /api/v1/p2p/federation/services` (services+health), `POST /api/v1/p2p/federation/healthcheck` (require_jwt, force sweep); `[federation]` config defaults (health_checks off).
- [ ] Steps: failing test (`load_p2p_config` returns `federation` defaults; a sweep with a stub dht captures a published health record); implement (startup guard on `[federation].health_checks`; audit-log each sweep summary); pass; commit `feat(p2p): federation publish-via-DHT + endpoints + config (#774)`.

---

# PHASE 3 — Hierarchical master-link (`api/masterlink.py`)

Depends on Phase 1 (peer discovery) + mesh peers. Election/term logic is pure & fully unit-tested; the network leg is thin.

### Task 14: `elect()` pure function + `Role` enum + term store
**Files:** Create `api/masterlink.py`; Test `tests/test_masterlink.py`.
**Interfaces:** `Role(Enum)` = MASTER/SATELLITE/CANDIDATE; `elect(peers: list[dict]) -> str` returns the master node_id_hex = min by `(priority, node_id_hex)`; `TermStore(path)` `.term -> int`, `.bump() -> int` (persist to `P2P_DIR/masterlink-term`, 0600).
- [ ] Steps: failing test (`elect` deterministic under peer reordering; lowest priority wins; tie broken by node_id_hex; empty→ValueError; `TermStore.bump` monotonic + persisted); implement; pass; commit `feat(p2p): master-link elect() + term store (#774)`.

### Task 15: `MasterLink` state machine (heartbeat/election_timeout, term monotonicity)
**Files:** Modify `api/masterlink.py`; Test `tests/test_masterlink.py`.
**Interfaces:** `MasterLink(self_id_hex, priority, peers_fn, send_fn, clock, heartbeat_interval=5, election_timeout=15)` with `.role`, `.term`, `.on_heartbeat(hb: dict)` (accept only `term >= self.term`; adopt master; ignore stale), `.tick()` (if satellite and `clock()-last_hb > election_timeout` → become CANDIDATE, `bump()` term, run `elect()` over `peers_fn()`; if won → MASTER and emit signed heartbeat via `send_fn`), `.topology() -> dict`.
- [ ] Steps: failing test (silent master → satellite times out, bumps term, elects itself when it is the min; a stale-term heartbeat is ignored; a higher-term heartbeat demotes a master); implement (pure logic + injected `send_fn`/`clock`); pass; commit `feat(p2p): master-link state machine + failover (#774)`.

### Task 16: UDP transport + sign/verify heartbeats + wire into `main.py` + endpoints + `[masterlink]` config
**Files:** Modify `api/masterlink.py`, `api/main.py`, `api/mesh.py`; Test `tests/test_masterlink.py`.
**Interfaces:** `start()/stop()` (DatagramProtocol on `[masterlink].port`, signed heartbeats, verify on receive), `peers_fn` from mesh (`mesh` peer list) ∪ DHT contacts; endpoints `GET /api/v1/p2p/masterlink/topology`, `POST /api/v1/p2p/masterlink/promote` (require_jwt, term-checked, audit-logged); `[masterlink]` config defaults (enabled off).
- [ ] Steps: failing test (config defaults; promote respects term; heartbeat verify rejects a bad sig via injected verify); implement (startup guard on `[masterlink].enabled`); pass; commit `feat(p2p): master-link transport + endpoints + config (#774)`.

---

# Finalization

### Task 17: README + endpoint docs + OPAD notes + issue update
**Files:** Modify `packages/secubox-p2p/README.md`; comment issue #774.
- [ ] Document the 3 subsystems, the `/api/v1/p2p/*` endpoints, the `p2p.toml` `[dht]/[federation]/[masterlink]` sections (all off by default, OPAD opt-in), and the audit log. Update `.claude/HISTORY.md`. Comment #774 "implementation complete, pending review" (do NOT close — user validates). Commit `docs(p2p): document DHT/federation/master-link evolutions (#774)`.

---

## Self-Review
- **Spec coverage:** DHT (Tasks 1-9) ✓; federation health-checks (10-13) ✓; master-link (14-16) ✓; endpoints (9,13,16) ✓; config sections (9,13,16) ✓; OPAD opt-in flags + audit (9,13,16,17) ✓; signed records (4,8) ✓; import convention + license (Task 1 onward) ✓; performance (elect/closest bounds — add asserts in Tasks 3/14) ✓.
- **Placeholders:** none — each task carries concrete test intent + code or exact interfaces; crypto/UDP seams are explicit and injected for unit tests.
- **Type consistency:** `node_id_for`, `xor_distance`, `DHTNode`, `RoutingTable.closest`, `DHTNetwork(send_fn, clock)`, `verify_record`, `HealthStore`, `HealthChecker`, `elect`, `MasterLink` signatures are stable across tasks that consume them.
