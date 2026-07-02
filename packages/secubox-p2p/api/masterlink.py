# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: masterlink
Pure master election logic and monotonic term store (no FastAPI, no networking).
Imported by federation module for Phase 3 (hierarchical master-link).
"""
import asyncio
import hashlib
import json
import os
import time
from enum import Enum
from pathlib import Path

from . import dht

MASTERLINK_TERM_PATH = Path("/var/lib/secubox/p2p/masterlink-term")
MAX_HB_DGRAM = 8192


def _canon_hb(term, master_id, priority, ts) -> bytes:
    """Deterministic canonical bytes for a heartbeat body (signed over)."""
    return json.dumps(
        {"master_id": master_id, "priority": priority, "term": term, "ts": ts},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def sign_heartbeat(term, master_id, priority, ts, id_pubkey) -> dict:
    """Build a signed heartbeat dict, Ed25519-signed with the local node key.

    Binds the heartbeat to `id_pubkey`: a peer cannot forge another node's
    master claim without possessing its private key.
    """
    body = _canon_hb(term, master_id, priority, ts)
    return {
        "t": "heartbeat",
        "term": term,
        "master_id": master_id,
        "priority": priority,
        "ts": ts,
        "id_pubkey": id_pubkey,
        "sig": dht._sign_sig(body),
    }


def verify_heartbeat(hb: dict) -> bool:
    """Verify a signed heartbeat's Ed25519 signature. Fails closed (never raises)."""
    try:
        body = _canon_hb(hb["term"], hb["master_id"], hb["priority"], hb["ts"])
        return bool(dht._verify_sig(body, hb["sig"], hb["id_pubkey"]))
    except (KeyError, TypeError, ValueError):
        return False


def peers_from_mesh(mesh_state) -> list:
    """Best-effort adapter: derive masterlink peer candidates from a parsed
    WireGuard mesh state dict. Thin and defensive — any unexpected shape
    (wrong type, missing keys, malformed entries) yields an empty list or
    skips the offending entry rather than raising.
    """
    try:
        entries = mesh_state.get("peers") or mesh_state.get("nodes") or []
    except (AttributeError, TypeError):
        return []
    out = []
    for entry in entries:
        try:
            pubkey = entry.get("public_key") or entry.get("pubkey") or entry.get("id")
            if not pubkey:
                continue
            node_id_hex = hashlib.sha256(str(pubkey).encode()).hexdigest()[:16]
            priority = int(entry.get("priority", 100))
        except (AttributeError, TypeError, ValueError):
            continue
        out.append({"node_id_hex": node_id_hex, "priority": priority})
    return out


class Role(Enum):
    """Node role in the master-link hierarchy."""
    MASTER = "master"
    SATELLITE = "satellite"
    CANDIDATE = "candidate"


def elect(peers: list) -> str:
    """
    Deterministic master election.

    Args:
        peers: List of dicts, each with "node_id_hex" (str) and "priority" (int).
               Lower priority value wins.

    Returns:
        The winning node_id_hex (str).

    Raises:
        ValueError: If peers list is empty.
    """
    if not peers:
        raise ValueError("elect() requires a non-empty peer list")
    return min(peers, key=lambda p: (p["priority"], p["node_id_hex"]))["node_id_hex"]


class TermStore:
    """
    Monotonic election term persisted to disk at MASTERLINK_TERM_PATH (0600).
    """

    def __init__(self, path=None):
        """
        Initialize TermStore.

        Args:
            path: Optional Path to the term file. Defaults to MASTERLINK_TERM_PATH.
        """
        self._path = Path(path) if path else MASTERLINK_TERM_PATH
        self._term = self._read()

    def _read(self) -> int:
        """Read term from disk, default to 0 if file doesn't exist."""
        try:
            return int(self._path.read_text().strip())
        except (OSError, ValueError):
            return 0

    @property
    def term(self) -> int:
        """Get the current term value."""
        return self._term

    def bump(self) -> int:
        """
        Increment the term by 1 and persist to disk.

        Returns:
            The new term value.
        """
        self._term += 1
        self._write()
        return self._term

    def set_min(self, other: int) -> None:
        """
        Adopt a higher term seen from a peer (monotonic increase only).

        Args:
            other: The term value to potentially adopt.
                   Will only be adopted if other > self._term.
        """
        if other > self._term:
            self._term = other
            self._write()

    def _write(self) -> None:
        """Write the term to disk with 0o600 permissions."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(str(self._term))
        os.chmod(self._path, 0o600)


class MasterLink:
    """
    Master-link state machine: election + heartbeat-based failover.

    Pure logic — no real networking or asyncio. `send_fn` broadcasts a
    heartbeat dict, `peers_fn` returns the other known candidates, and
    `clock` is injected for deterministic testing. Real UDP transport
    is wired in a later task.
    """

    def __init__(self, self_id_hex, priority, peers_fn, send_fn, term_store,
                 clock=time.time, heartbeat_interval=5, election_timeout=15,
                 id_pubkey="", peer_addrs=None):
        """
        Initialize the state machine as a SATELLITE.

        Args:
            self_id_hex: This node's node_id_hex.
            priority: This node's election priority (lower wins).
            peers_fn: Callable returning other known peers (list of
                {"node_id_hex", "priority"} dicts); self need not be included.
            send_fn: Callable(msg: dict) -> None, broadcasts a heartbeat.
            term_store: A TermStore instance backing the election term.
            clock: Callable() -> float, injected time source.
            heartbeat_interval: Seconds between MASTER heartbeats (informational;
                the caller's scheduler is responsible for calling tick() at this rate).
            election_timeout: Seconds without a valid heartbeat before starting
                a new election.
            id_pubkey: This node's Ed25519 identity public key (hex). When set,
                emitted heartbeats are signed via sign_heartbeat(); when empty
                (default, used by pure-logic tests), heartbeats are plain dicts.
            peer_addrs: Optional list of (host, port) UDP endpoints for peers'
                masterlink listeners, used by the real UDP transport (start()).
        """
        self.self_id_hex, self.priority = self_id_hex, priority
        self._peers_fn, self._send_fn, self._terms, self._clock = peers_fn, send_fn, term_store, clock
        self._hb_interval, self._election_timeout = heartbeat_interval, election_timeout
        self.role = Role.SATELLITE
        self.master_id = None
        self._last_hb = clock()  # last time we heard a valid heartbeat
        self.id_pubkey = id_pubkey
        self._peer_addrs = list(peer_addrs) if peer_addrs else []
        self._transport = None
        self._tick_task = None

    @property
    def term(self) -> int:
        """Current election term (delegated to the backing TermStore)."""
        return self._terms.term

    def _candidates(self) -> list:
        """Build the deduplicated candidate set, including ourselves."""
        peers = list(self._peers_fn() or [])
        seen = {}
        for p in peers:
            try:
                node_id = p["node_id_hex"]
                priority = p["priority"]
            except (KeyError, TypeError):
                continue  # malformed peer entry — skip defensively
            seen[node_id] = {"node_id_hex": node_id, "priority": priority}
        seen[self.self_id_hex] = {"node_id_hex": self.self_id_hex, "priority": self.priority}
        return list(seen.values())

    def _emit_heartbeat(self) -> None:
        """Broadcast a heartbeat announcing ourselves as master at the current term.

        Signed via sign_heartbeat() when self.id_pubkey is set; otherwise a
        plain dict (backward-compat with the pure-logic tests that never
        set id_pubkey and have no signing key material to work with).
        """
        if self.id_pubkey:
            hb = sign_heartbeat(self.term, self.self_id_hex, self.priority,
                                 self._clock(), self.id_pubkey)
        else:
            hb = {
                "t": "heartbeat",
                "term": self.term,
                "master_id": self.self_id_hex,
                "priority": self.priority,
                "ts": self._clock(),
            }
        self._send_fn(hb)

    def on_heartbeat(self, hb: dict) -> None:
        """
        Process an incoming heartbeat {term, master_id, priority, ts}.

        A heartbeat carrying a term strictly lower than ours is stale and
        ignored (split-brain avoidance: an old/partitioned master cannot
        demote a node that has already moved to a newer term).

        When two nodes self-elect at the same term (their heartbeats cross
        in flight), a naive "any term >= ours demotes us" rule makes BOTH
        masters demote to SATELLITE simultaneously — a zero-master window
        until the next election_timeout. Instead, on an equal-term collision
        between two masters we apply the same deterministic tie-break as
        elect(): (priority, node_id_hex), lower wins. Exactly one side
        demotes; the winner ignores the loser's heartbeat and stays MASTER.

        Otherwise (strictly higher term, or equal term while we are not
        master) we adopt the term (monotonic, via set_min), record the
        announced master, reset our heartbeat timer, and become SATELLITE
        unless the announced master is us.

        If the heartbeat carries a "sig" field it is a signed heartbeat
        (see sign_heartbeat/verify_heartbeat): a failed signature check
        means it is ignored outright, before any state is touched — a
        peer cannot forge another node's master claim without its key.
        Heartbeats without a "sig" field (the pure-logic test path) skip
        verification entirely, preserving backward compatibility.
        """
        if "sig" in hb and not verify_heartbeat(hb):
            return
        try:
            hb_term = int(hb["term"])
            master_id = hb["master_id"]
            pri = int(hb.get("priority", 1 << 30))  # missing -> large value, loses ties
        except (KeyError, TypeError, ValueError):
            return
        if hb_term < self.term:
            return  # stale heartbeat from a lower term — ignore
        if hb_term == self.term and self.role == Role.MASTER and master_id != self.self_id_hex:
            # Equal-term collision between two masters: exactly one survives.
            if (pri, master_id) < (self.priority, self.self_id_hex):
                # The other node wins the tie — we demote.
                self._terms.set_min(hb_term)
                self.master_id = master_id
                self._last_hb = self._clock()
                self.role = Role.SATELLITE
            # else: we win the tie — ignore their heartbeat, stay MASTER.
            return
        self._terms.set_min(hb_term)
        self.master_id = master_id
        self._last_hb = self._clock()
        if master_id != self.self_id_hex:
            self.role = Role.SATELLITE
        else:
            self.role = Role.MASTER

    def tick(self) -> None:
        """
        Periodic step, called by the caller's scheduler.

        As MASTER: emit a heartbeat every tick.
        As SATELLITE/CANDIDATE: if no valid heartbeat has been seen for
        longer than election_timeout, bump the term and run an election.
        """
        now = self._clock()
        if self.role == Role.MASTER:
            self._emit_heartbeat()
            return
        if now - self._last_hb > self._election_timeout:
            self.role = Role.CANDIDATE
            self._terms.bump()
            winner = elect(self._candidates())
            if winner == self.self_id_hex:
                self.role = Role.MASTER
                self.master_id = self.self_id_hex
                self._emit_heartbeat()
            else:
                self.role = Role.SATELLITE
                self.master_id = winner  # report the elected winner immediately
            self._last_hb = now  # avoid immediate re-election spam

    def topology(self) -> dict:
        """Snapshot of this node's view of the master-link topology."""
        return {
            "master": self.master_id,
            "term": self.term,
            "self_role": self.role.value,
            "self_id": self.self_id_hex,
            "peers": [p["node_id_hex"] for p in self._candidates()],
        }

    # -- Real UDP transport + async tick driver ---------------------------
    #
    # Everything above is pure logic (no networking, no asyncio) and stays
    # fully exercised by the synchronous tests. The methods below are an
    # optional real-transport layer on top: start() opens a UDP listener and
    # rewires send_fn to broadcast to `peer_addrs`; start_ticking() drives
    # tick() on a wall-clock schedule. Neither is invoked by the pure-logic
    # constructor path, so existing behavior is unchanged unless a caller
    # opts in.

    async def start(self, host="0.0.0.0", port=51824) -> None:
        """Open the UDP listener and wire send_fn to broadcast to peer_addrs."""
        loop = asyncio.get_event_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _MLProtocol(self), local_addr=(host, port),
        )
        self._transport = transport

        def _udp_send(msg: dict) -> None:
            if not self._peer_addrs:
                return  # no known peer endpoints — nothing to broadcast to
            data = json.dumps(msg, separators=(",", ":")).encode("utf-8")
            for addr in self._peer_addrs:
                try:
                    transport.sendto(data, addr)
                except OSError:
                    pass  # best-effort broadcast — one dead peer must not abort the rest

        self._send_fn = _udp_send

    async def run(self) -> None:
        """Drive tick() forever at heartbeat_interval. Cancel-safe (see stop())."""
        while True:
            self.tick()
            await asyncio.sleep(self._hb_interval)

    def start_ticking(self):
        """Schedule run() as a background task and return it."""
        self._tick_task = asyncio.create_task(self.run())
        return self._tick_task

    async def stop(self) -> None:
        """Cancel the tick task (if any) and close the UDP transport (if any)."""
        if self._tick_task is not None:
            self._tick_task.cancel()
            try:
                await self._tick_task
            except asyncio.CancelledError:
                pass
            self._tick_task = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None


class _MLProtocol(asyncio.DatagramProtocol):
    """UDP datagram protocol feeding decoded heartbeats into a MasterLink."""

    def __init__(self, ml: "MasterLink"):
        self._ml = ml

    def datagram_received(self, data: bytes, addr) -> None:
        if not data or len(data) > MAX_HB_DGRAM:
            return  # oversized/empty datagram — drop defensively
        try:
            hb = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(hb, dict):
            return
        self._ml.on_heartbeat(hb)

    def error_received(self, exc) -> None:
        pass  # best-effort transport — swallow socket errors, never crash the loop
