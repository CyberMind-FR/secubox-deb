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
