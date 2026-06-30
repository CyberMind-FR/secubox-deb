# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: log
Append-only BLAKE2b-chained journal on SQLite (WAL mode).

Design:
  - No UPDATE or DELETE — append-only, as required by CSPN immutable audit posture.
  - Signature is VERIFIED before storing — a bad sig is rejected before chaining.
  - The chain: entry_hash = BLAKE2b-256(prev_hash || canonical_payload || sig).
    Tampering with any entry breaks all subsequent hashes → detectable by verify_chain().
  - Merkle root over all entry_hash values enables WitnessAttest co-signatures
    (CONIKS-style equivocation detection).
  - Thread-safe: a threading.Lock serializes all appends.

Runtime path:
  /var/lib/secubox/annuaire/log.db  (production)
  Passed as db_path parameter for tests (tmp dir).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Iterator, Optional

from .model import GENESIS_HASH, LogEntry, Op, compute_entry_hash, now_rfc3339
from .crypto import canonical_bytes, verify


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS log (
    height       INTEGER PRIMARY KEY,
    op           TEXT    NOT NULL,
    prev_hash    TEXT    NOT NULL,
    payload_type TEXT    NOT NULL,
    payload      TEXT    NOT NULL,   -- canonical JSON bytes stored as UTF-8 text
    author       TEXT    NOT NULL,
    sig          TEXT    NOT NULL,
    entry_hash   TEXT    NOT NULL UNIQUE,
    created_at   TEXT    NOT NULL
);
"""

_CREATE_INDEX_AUTHOR = "CREATE INDEX IF NOT EXISTS idx_author ON log(author);"


class Journal:
    """Append-only, BLAKE2b-chained audit journal.

    The only mutation method is append().  There is no delete(), no update().
    Tampering with the underlying SQLite file is detectable via verify_chain().

    Thread safety: a single Lock serializes all appends.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # -----------------------------------------------------------------------
    # Internal DB helpers
    # -----------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, isolation_level=None)  # autocommit mode
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        return con

    def _init_db(self) -> None:
        con = self._connect()
        try:
            con.execute(_CREATE_TABLE)
            con.execute(_CREATE_INDEX_AUTHOR)
        finally:
            con.close()

    def _head(self, con: sqlite3.Connection) -> tuple[int, str]:
        """Return (height, entry_hash) of the chain head, or (-1, GENESIS_HASH)."""
        row = con.execute(
            "SELECT height, entry_hash FROM log ORDER BY height DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (-1, GENESIS_HASH)

    def _author_pubkey(self, con: sqlite3.Connection, author_did: str) -> Optional[str]:
        """Extract pubkey hex from the most recent Identity entry for author_did."""
        row = con.execute(
            """
            SELECT payload FROM log
            WHERE author = ? AND payload_type = 'Identity'
            ORDER BY height DESC LIMIT 1
            """,
            (author_did,),
        ).fetchone()
        if not row:
            return None
        payload = json.loads(row[0])
        return payload.get("pubkey")

    # -----------------------------------------------------------------------
    # Append
    # -----------------------------------------------------------------------

    def append(
        self,
        op: Op,
        payload_type: str,
        payload: dict,
        author: str,
        sig: str,
        created_at: Optional[str] = None,
        author_pubkey_hex: Optional[str] = None,
    ) -> LogEntry:
        """Append a signed object as the next chain link.

        Verification (in order):
          1. The author's pubkey is resolved.  Priority:
             a. *author_pubkey_hex* if passed explicitly (caller has the key in hand).
             b. Most recent Identity entry in the log for this author.
             c. If payload_type == 'Identity' and payload['did'] == author,
                use payload['pubkey'] (bootstrap: first Identity entry).
          2. The sig is verified against canonical_bytes(payload).
          3. On success: entry_hash is computed and the row is inserted atomically.

        Args:
            op: operation type (Op enum).
            payload_type: class name of the embedded object ("Identity", "Attestation", …).
            payload: the signed object as a plain dict.
            author: the did:plc of the signer.
            sig: hex Ed25519 signature over canonical_bytes(payload).
            created_at: RFC 3339 timestamp; defaults to now_rfc3339().
            author_pubkey_hex: optional override for the author's public key hex.
                Useful when the pubkey is not yet in the log (first entry per author).

        Raises:
            ValueError: if the signature cannot be verified.

        Returns:
            The committed LogEntry.
        """
        if created_at is None:
            created_at = now_rfc3339()

        canonical = canonical_bytes(payload)

        with self._lock:
            con = self._connect()
            try:
                prev_height, prev_hash = self._head(con)

                # Resolve the author's pubkey for verification
                pub_hex: Optional[str] = author_pubkey_hex

                if pub_hex is None:
                    pub_hex = self._author_pubkey(con, author)

                if pub_hex is None:
                    # Bootstrap: first Identity entry may carry its own pubkey
                    if payload_type == "Identity" and payload.get("did") == author:
                        pub_hex = payload.get("pubkey")

                if pub_hex is None:
                    raise ValueError(
                        f"signature verification failed — no known pubkey for {author}"
                    )

                if not verify(pub_hex, canonical, sig):
                    raise ValueError(
                        f"signature verification failed — refusing to chain"
                    )

                entry_hash = compute_entry_hash(prev_hash, canonical, sig)
                height = prev_height + 1

                con.execute("BEGIN IMMEDIATE;")
                con.execute(
                    "INSERT INTO log VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        height,
                        op.value if isinstance(op, Op) else op,
                        prev_hash,
                        payload_type,
                        canonical.decode("utf-8"),
                        author,
                        sig,
                        entry_hash,
                        created_at,
                    ),
                )
                con.execute("COMMIT;")

                return LogEntry(
                    height=height,
                    op=op,
                    prev_hash=prev_hash,
                    payload_type=payload_type,
                    payload=payload,
                    author=author,
                    sig=sig,
                    entry_hash=entry_hash,
                    created_at=created_at,
                )
            except Exception:
                try:
                    con.execute("ROLLBACK;")
                except Exception:
                    pass
                raise
            finally:
                con.close()

    # -----------------------------------------------------------------------
    # Chain verification (tamper detection)
    # -----------------------------------------------------------------------

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Walk the chain; recompute every entry_hash.

        Any mismatch between stored and recomputed values is a tamper signal.
        Also checks that each entry's prev_hash matches the preceding entry's hash.

        Returns:
            (True, None) if the chain is intact.
            (False, broken_at_height) if tampering is detected.
        """
        con = self._connect()
        try:
            prev = GENESIS_HASH
            for row in con.execute(
                "SELECT height, op, prev_hash, payload, sig, entry_hash "
                "FROM log ORDER BY height"
            ):
                height, op, prev_hash, payload_text, sig, stored_hash = row

                if prev_hash != prev:
                    return False, height

                recomputed = compute_entry_hash(
                    prev_hash, payload_text.encode("utf-8"), sig
                )
                if recomputed != stored_hash:
                    return False, height

                prev = stored_hash

            return True, None
        finally:
            con.close()

    # -----------------------------------------------------------------------
    # Merkle root
    # -----------------------------------------------------------------------

    def merkle_root(self) -> str:
        """Compute a BLAKE2b-256 Merkle root over all entry_hash leaves.

        Witnesses co-sign this root (WitnessAttest).  Clients compare published
        roots across witnesses to detect equivocation (CONIKS).

        Returns GENESIS_HASH for an empty journal.
        """
        con = self._connect()
        try:
            leaves = [
                bytes.fromhex(row[0])
                for row in con.execute(
                    "SELECT entry_hash FROM log ORDER BY height"
                )
            ]
        finally:
            con.close()

        if not leaves:
            return GENESIS_HASH

        level = leaves
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left  # duplicate odd leaf
                nxt.append(hashlib.blake2b(left + right, digest_size=32).digest())
            level = nxt

        return level[0].hex()

    # -----------------------------------------------------------------------
    # Query helpers
    # -----------------------------------------------------------------------

    def tip(self) -> Optional[LogEntry]:
        """Return the most recent LogEntry, or None if the journal is empty."""
        con = self._connect()
        try:
            row = con.execute(
                "SELECT height, op, prev_hash, payload_type, payload, "
                "author, sig, entry_hash, created_at "
                "FROM log ORDER BY height DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            height, op, prev_hash, payload_type, payload_text, author, sig, entry_hash, created_at = row
            return LogEntry(
                height=height,
                op=Op(op),
                prev_hash=prev_hash,
                payload_type=payload_type,
                payload=json.loads(payload_text),
                author=author,
                sig=sig,
                entry_hash=entry_hash,
                created_at=created_at,
            )
        finally:
            con.close()

    def iter_entries(self) -> Iterator[LogEntry]:
        """Iterate all entries in height order (oldest first)."""
        con = self._connect()
        try:
            for row in con.execute(
                "SELECT height, op, prev_hash, payload_type, payload, "
                "author, sig, entry_hash, created_at "
                "FROM log ORDER BY height"
            ):
                height, op, prev_hash, payload_type, payload_text, author, sig, entry_hash, created_at = row
                yield LogEntry(
                    height=height,
                    op=Op(op),
                    prev_hash=prev_hash,
                    payload_type=payload_type,
                    payload=json.loads(payload_text),
                    author=author,
                    sig=sig,
                    entry_hash=entry_hash,
                    created_at=created_at,
                )
        finally:
            con.close()
