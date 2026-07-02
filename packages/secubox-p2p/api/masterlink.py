# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: masterlink
Pure master election logic and monotonic term store (no FastAPI, no networking).
Imported by federation module for Phase 3 (hierarchical master-link).
"""
import os
import time
from enum import Enum
from pathlib import Path

MASTERLINK_TERM_PATH = Path("/var/lib/secubox/p2p/masterlink-term")


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
                 clock=time.time, heartbeat_interval=5, election_timeout=15):
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
        """
        self.self_id_hex, self.priority = self_id_hex, priority
        self._peers_fn, self._send_fn, self._terms, self._clock = peers_fn, send_fn, term_store, clock
        self._hb_interval, self._election_timeout = heartbeat_interval, election_timeout
        self.role = Role.SATELLITE
        self.master_id = None
        self._last_hb = clock()  # last time we heard a valid heartbeat

    @property
    def term(self) -> int:
        """Current election term (delegated to the backing TermStore)."""
        return self._terms.term

    def _candidates(self) -> list:
        """Build the deduplicated candidate set, including ourselves."""
        peers = list(self._peers_fn() or [])
        peers.append({"node_id_hex": self.self_id_hex, "priority": self.priority})
        seen = {}
        for p in peers:
            seen[p["node_id_hex"]] = p
        return list(seen.values())

    def _emit_heartbeat(self) -> None:
        """Broadcast a heartbeat announcing ourselves as master at the current term."""
        self._send_fn({"t": "heartbeat", "term": self.term, "master_id": self.self_id_hex, "ts": self._clock()})

    def on_heartbeat(self, hb: dict) -> None:
        """
        Process an incoming heartbeat {term, master_id, ts}.

        A heartbeat carrying a term strictly lower than ours is stale and
        ignored (split-brain avoidance: an old/partitioned master cannot
        demote a node that has already moved to a newer term). Otherwise
        we adopt the term (monotonic, via set_min), record the announced
        master, reset our heartbeat timer, and become SATELLITE unless the
        announced master is us.
        """
        try:
            hb_term = int(hb["term"])
            master_id = hb["master_id"]
        except (KeyError, TypeError, ValueError):
            return
        if hb_term < self.term:
            return  # stale heartbeat from a lower term — ignore
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
