# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-p2p :: Kademlia DHT (custom, asyncio/UDP). Issue #774."""
from __future__ import annotations
import asyncio
import hashlib
import json as _json
import time
import uuid
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


def canonical_record(did: str, id_pubkey: str, wg_pubkey: str, endpoint: str, ts: int) -> bytes:
    """Deterministic signed reachability record (canonical JSON form).

    `id_pubkey` is the node's Ed25519 identity public key (hex), from which
    `did` derives and against which `sig` is verified. `wg_pubkey` is the
    node's separate WireGuard X25519 public key (hex) — it cannot sign, it
    is merely advertised as the mesh endpoint's transport key.
    """
    return _json.dumps(
        {"did": did, "endpoint": endpoint, "id_pubkey": id_pubkey,
         "ts": ts, "wg_pubkey": wg_pubkey},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def _did_from_pubkey(pub_hex: str) -> str:
    """Convert an Ed25519 identity pubkey (hex) to its did:plc identifier."""
    return _annuaire.did_from_pubkey_hex(pub_hex)


def _verify_sig(body: bytes, sig_hex: str, id_pub_hex: str) -> bool:
    """Verify an Ed25519 signature over `body` using the given identity pubkey (hex)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(id_pub_hex))
        pub_key.verify(bytes.fromhex(sig_hex), body)
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False


def _sign_sig(body: bytes) -> str:
    """Sign `body` with the local node's Ed25519 identity key (hex signature)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _did, priv_hex = _annuaire.node_identity()
    if priv_hex is None:
        raise RuntimeError("node identity unavailable: cannot sign DHT record")
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv_key.sign(body).hex()


def sign_record(did: str, id_pubkey: str, wg_pubkey: str, endpoint: str, ts: int) -> dict:
    """Sign a reachability record and return with sig field."""
    body = canonical_record(did, id_pubkey, wg_pubkey, endpoint, ts)
    return {"did": did, "id_pubkey": id_pubkey, "wg_pubkey": wg_pubkey,
            "endpoint": endpoint, "ts": ts, "sig": _sign_sig(body)}


def verify_record(rec: dict) -> bool:
    """Verify a reachability record: check sig, DID validity, and canonical bytes."""
    try:
        if "sig" not in rec:
            return False
        body = canonical_record(rec["did"], rec["id_pubkey"], rec["wg_pubkey"],
                                 rec["endpoint"], rec["ts"])
        if _did_from_pubkey(rec["id_pubkey"]) != rec["did"]:
            return False
        return bool(_verify_sig(body, rec["sig"], rec["id_pubkey"]))
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

    def __init__(self, did: str, id_pubkey: str, wg_pubkey: str, endpoint: str,
                 send_fn=None, clock=time.time):
        self.did = did
        self.self_id = node_id_for(did)
        self.id_pubkey = id_pubkey
        self.wg_pubkey = wg_pubkey
        self.endpoint = endpoint
        self.send_fn = send_fn
        self._clock = clock
        self.routing = RoutingTable(self.self_id)
        self.store: dict = {}  # key_hex -> (record, expiry_ts)
        self.pending: dict = {}  # rpc_id -> asyncio.Future, resolved by handle_message

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
        elif t in ("pong", "nodes", "value", "ok"):
            fut = self.pending.get(rpc_id)
            if fut is not None and not fut.done():
                fut.set_result(msg)

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

    # -- Task 7: iterative lookup / find_peer / announce (injected transport) --

    async def _rpc(self, node: "DHTNode", msg: dict):
        """Send `msg` to `node` and await the matching reply, or None on timeout."""
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        rpc_id = msg["rpc_id"]
        self.pending[rpc_id] = fut
        try:
            self.send_fn(encode_msg(msg), node.endpoint)
            return await asyncio.wait_for(fut, RPC_TIMEOUT)
        except asyncio.TimeoutError:
            return None
        finally:
            self.pending.pop(rpc_id, None)

    def _merge_contact(self, shortlist: list, contact: dict) -> None:
        """Parse a {node_id_hex,did,endpoint} contact dict and merge into shortlist
        (dedup by node_id, skip self). Malformed/peer-controlled contacts (bad hex,
        endpoint without a port, missing fields, wrong types) are discarded rather
        than allowed to raise — a single bad peer must never crash a lookup."""
        try:
            node_id = bytes.fromhex(contact["node_id_hex"])
            did = contact["did"]
            endpoint = self._parse_endpoint(contact["endpoint"])
        except (ValueError, KeyError, TypeError):
            return
        if node_id == self.self_id:
            return
        if any(n.node_id == node_id for n in shortlist):
            return
        shortlist.append(DHTNode(node_id, did, endpoint))

    async def iterative_find(self, target_id: bytes, mode: str):
        """Classic Kademlia iterative lookup, alpha-parallel, over the injected
        transport. mode == "node" -> return the k closest DHTNode's found.
        mode == "value" -> return the first verified record found, or None."""
        shortlist: list = list(self.routing.closest(target_id, KAD_K))
        queried: set = {self.self_id}
        best_dist = min((xor_distance(n.node_id, target_id) for n in shortlist), default=None)

        while True:
            candidates = [
                n for n in sorted(shortlist, key=lambda n: xor_distance(n.node_id, target_id))
                if n.node_id not in queried
            ][:KAD_ALPHA]
            if not candidates:
                break
            for n in candidates:
                queried.add(n.node_id)

            tasks = []
            for n in candidates:
                rpc_id = uuid.uuid4().hex
                if mode == "value":
                    msg = msg_find_value(rpc_id, self._sender_dict(), target_id.hex())
                else:
                    msg = msg_find_node(rpc_id, self._sender_dict(), target_id.hex())
                tasks.append(self._rpc(n, msg))
            replies = await asyncio.gather(*tasks, return_exceptions=True)

            found_value = None
            for reply in replies:
                if reply is None or isinstance(reply, BaseException):
                    # No reply, timeout, or a transport-level exception (e.g. a
                    # future real-UDP send_fn failure): treat like a no-reply
                    # and keep going with the rest of the lookup.
                    continue
                sender = reply.get("sender")
                if isinstance(sender, dict):
                    self._touch_sender(sender)
                if mode == "value" and reply.get("t") == "value":
                    rec = reply.get("value")
                    if rec is not None and verify_record(rec):
                        found_value = rec
                    continue
                if reply.get("t") == "nodes":
                    for contact in reply.get("nodes", []):
                        self._merge_contact(shortlist, contact)

            # Cap the shortlist to the KAD_K closest-to-target contacts so a
            # peer returning many fabricated "close" contacts can't inflate
            # it and force extra RPC rounds.
            shortlist.sort(key=lambda n: xor_distance(n.node_id, target_id))
            del shortlist[KAD_K:]

            if found_value is not None:
                return found_value

            new_best = min((xor_distance(n.node_id, target_id) for n in shortlist), default=best_dist)
            if best_dist is not None and (new_best is None or new_best >= best_dist):
                break
            best_dist = new_best

        if mode == "value":
            return None
        shortlist.sort(key=lambda n: xor_distance(n.node_id, target_id))
        return shortlist[:KAD_K]

    async def find_peer(self, did: str):
        """Resolve a DID to its verified reachability record via iterative_find."""
        return await self.iterative_find(node_id_for(did), "value")

    async def announce(self) -> None:
        """Sign our own reachability record, store it locally, then push it to
        the k nodes closest to our own id (as discovered via iterative_find)."""
        record = sign_record(self.did, self.id_pubkey, self.wg_pubkey, self.endpoint, int(self._clock()))
        key_hex = self.self_id.hex()
        self.local_store_put(key_hex, record)
        closest = await self.iterative_find(self.self_id, "node")
        for node in closest:
            rpc_id = uuid.uuid4().hex
            msg = msg_store(rpc_id, self._sender_dict(), key_hex, record)
            await self._rpc(node, msg)
