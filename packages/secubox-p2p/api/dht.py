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
