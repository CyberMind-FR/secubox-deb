# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-p2p :: Kademlia DHT (custom, asyncio/UDP). Issue #774."""
from __future__ import annotations
import hashlib
import json as _json
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from . import annuaire_client as _annuaire

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


@dataclass
class DHTNode:
    """A Kademlia DHT contact: node_id, DID, endpoint, last_seen."""
    node_id: bytes
    did: str
    endpoint: tuple  # (host, port)
    last_seen: float = 0.0


class DHTBucket:
    """A Kademlia k-bucket: LRU-ordered contacts, most-recent at the tail."""
    def __init__(self, k: int = KAD_K):
        self.k = k
        self._nodes: OrderedDict[bytes, DHTNode] = OrderedDict()

    def add(self, node: DHTNode) -> bool:
        """Add or refresh a node. Returns True if stored/refreshed, False if full."""
        node.last_seen = time.time()
        if node.node_id in self._nodes:
            self._nodes.move_to_end(node.node_id)   # refresh → tail (most-recent)
            self._nodes[node.node_id] = node
            return True
        if len(self._nodes) >= self.k:
            return False
        self._nodes[node.node_id] = node
        return True

    def remove(self, node_id: bytes) -> None:
        """Remove a node by id."""
        self._nodes.pop(node_id, None)

    def oldest(self):
        """Return the oldest (head) node, or None if empty."""
        return next(iter(self._nodes.values())) if self._nodes else None

    @property
    def nodes(self):
        """Return a list of all nodes in order."""
        return list(self._nodes.values())


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


def canonical_record(did: str, wg_pubkey: str, endpoint: str, ts: int) -> bytes:
    """Deterministic signed reachability record (canonical JSON form)."""
    return _json.dumps(
        {"did": did, "wg_pubkey": wg_pubkey, "endpoint": endpoint, "ts": ts},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def _did_from_pubkey(pub_hex: str) -> str:
    """Seam: convert wg_pubkey hex to DID. Real impl in Task 8 via annuaire_client."""
    return _annuaire.did_from_pubkey_hex(pub_hex)


def _verify_sig(body: bytes, sig_hex: str, pub_hex: str) -> bool:
    """Seam: verify Ed25519 signature. Real impl in Task 8."""
    raise NotImplementedError


def _sign_sig(body: bytes) -> str:
    """Seam: sign body with local key. Real impl in Task 8."""
    raise NotImplementedError


def sign_record(did: str, wg_pubkey: str, endpoint: str, ts: int) -> dict:
    """Sign a reachability record and return with sig field."""
    body = canonical_record(did, wg_pubkey, endpoint, ts)
    return {"did": did, "wg_pubkey": wg_pubkey, "endpoint": endpoint,
            "ts": ts, "sig": _sign_sig(body)}


def verify_record(rec: dict) -> bool:
    """Verify a reachability record: check sig, DID validity, and canonical bytes."""
    try:
        if "sig" not in rec:
            return False
        body = canonical_record(rec["did"], rec["wg_pubkey"], rec["endpoint"], rec["ts"])
        if _did_from_pubkey(rec["wg_pubkey"]) != rec["did"]:
            return False
        return bool(_verify_sig(body, rec["sig"], rec["wg_pubkey"]))
    except (KeyError, TypeError, ValueError):
        return False


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


class DHTNetwork:
    """Kademlia DHT node: routing table + local value store + message dispatch.

    The UDP transport is injected via `send_fn(data: bytes, addr: tuple)` so this
    class is unit-testable without real sockets. Iterative lookup and the real
    UDP transport are added in later tasks.
    """

    def __init__(self, did: str, wg_pubkey: str, endpoint: str,
                 send_fn=None, clock=time.time):
        self.did = did
        self.self_id = node_id_for(did)
        self.wg_pubkey = wg_pubkey
        self.endpoint = endpoint
        self.send_fn = send_fn
        self._clock = clock
        self.routing = RoutingTable(self.self_id)
        self.store: dict = {}  # key_hex -> (record, expiry_ts)

    def _sender_dict(self) -> dict:
        return {"node_id_hex": self.self_id.hex(), "did": self.did, "endpoint": self.endpoint}

    def _parse_endpoint(self, endpoint: str) -> tuple:
        host, port = endpoint.rsplit(":", 1)
        return (host, int(port))

    def _touch_sender(self, sender: dict) -> None:
        node = DHTNode(
            node_id=bytes.fromhex(sender["node_id_hex"]),
            did=sender["did"],
            endpoint=self._parse_endpoint(sender["endpoint"]),
        )
        self.routing.insert(node)

    def _contact_dicts(self, nodes) -> list:
        return [{"node_id_hex": n.node_id.hex(), "did": n.did,
                  "endpoint": f"{n.endpoint[0]}:{n.endpoint[1]}"} for n in nodes]

    def handle_message(self, data: bytes, addr) -> None:
        msg = decode_msg(data)
        if msg is None:
            return
        sender = msg.get("sender")
        if isinstance(sender, dict):
            self._touch_sender(sender)
        rpc_id = msg.get("rpc_id")
        t = msg.get("t")
        if t == "ping":
            self._reply(msg_pong(rpc_id, self._sender_dict()), addr)
        elif t == "find_node":
            target = bytes.fromhex(msg["target"])
            closest = self.routing.closest(target, KAD_K)
            self._reply(msg_nodes(rpc_id, self._sender_dict(), self._contact_dicts(closest)), addr)
        elif t == "find_value":
            key = msg["key"]
            record = self.local_store_get(key)
            if record is not None:
                self._reply(msg_value(rpc_id, self._sender_dict(), record), addr)
            else:
                target = bytes.fromhex(key)
                closest = self.routing.closest(target, KAD_K)
                self._reply(msg_nodes(rpc_id, self._sender_dict(), self._contact_dicts(closest)), addr)
        elif t == "store":
            self.local_store_put(msg["key"], msg["value"])
            self._reply(msg_ok(rpc_id, self._sender_dict()), addr)

    def _reply(self, msg: dict, addr) -> None:
        if self.send_fn is not None:
            self.send_fn(encode_msg(msg), addr)

    def local_store_put(self, key_hex: str, record: dict) -> bool:
        if not verify_record(record):
            return False
        self.store[key_hex] = (record, self._clock() + DHT_TTL)
        return True

    def local_store_get(self, key_hex: str):
        entry = self.store.get(key_hex)
        if entry is None:
            return None
        record, expiry = entry
        if self._clock() >= expiry:
            del self.store[key_hex]
            return None
        return record
