# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/alert_sink.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
Alert sink: persist anomalies to SQLite and broadcast them to live
SSE subscribers.

Privacy invariant: the `subscriber_hash` field is the HMAC-truncated
IMSI/TMSI as produced by sentinelle_gsm.observer.Anonymizer — NEVER
the plaintext identifier. The sink refuses to write if any field
matches the plaintext-IMSI shape (15 contiguous digits).
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import AsyncIterator, Optional


_PLAINTEXT_IMSI_RE = re.compile(r"\b\d{15}\b")


@dataclass
class Alert:
    id: int = 0
    ts: float = field(default_factory=time.time)
    cell_id: str = ""            # e.g. "208-01-100-12345"
    arfcn: int = 0
    score: int = 0               # 0..100
    reason: str = ""             # human-readable scoring reason
    subscriber_hash: Optional[str] = None   # HMAC-trunc, NEVER plaintext
    trusted_label: Optional[str] = None     # set by trusted-registry lookup


class AlertSink:
    """SQLite + asyncio pub/sub."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                cell_id TEXT NOT NULL,
                arfcn INTEGER NOT NULL,
                score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                subscriber_hash TEXT,
                trusted_label TEXT
            )
        """)
        self._db.execute("CREATE INDEX IF NOT EXISTS alerts_ts_idx ON alerts(ts)")
        self._db.commit()
        self._subscribers: list[asyncio.Queue[Alert]] = []

    def write(self, alert: Alert) -> Alert:
        # Privacy guard: reject anything that looks like plaintext IMSI
        for value in (alert.cell_id, alert.reason,
                      alert.subscriber_hash or "",
                      alert.trusted_label or ""):
            if _PLAINTEXT_IMSI_RE.search(value):
                raise ValueError("alert_sink: plaintext-IMSI shape detected — refusing write")

        cur = self._db.execute(
            "INSERT INTO alerts(ts, cell_id, arfcn, score, reason, subscriber_hash, trusted_label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (alert.ts, alert.cell_id, alert.arfcn, alert.score, alert.reason,
             alert.subscriber_hash, alert.trusted_label),
        )
        self._db.commit()
        alert.id = cur.lastrowid
        # Fan-out to live subscribers (non-blocking; drop on full)
        for q in list(self._subscribers):
            try:
                q.put_nowait(alert)
            except asyncio.QueueFull:
                pass
        return alert

    def list(self, limit: int = 100, since: float = 0.0) -> list[Alert]:
        rows = self._db.execute(
            "SELECT id, ts, cell_id, arfcn, score, reason, subscriber_hash, trusted_label "
            "FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
            (since, limit),
        ).fetchall()
        return [Alert(*r) for r in rows]

    def subscribe(self) -> asyncio.Queue[Alert]:
        q: asyncio.Queue[Alert] = asyncio.Queue(maxsize=64)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Alert]) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def stream(self) -> AsyncIterator[str]:
        """Yield SSE-formatted text/event-stream chunks.

        Emits a `: subscribed` SSE comment IMMEDIATELY so browsers see
        the first response body byte and transition `EventSource.readyState`
        from CONNECTING (0) to OPEN (1). Without this, the response would
        hang on `q.get()` until the first alert is written — browsers stay
        in CONNECTING and the UI shows "connecting…" forever.

        Also emits a `: ping` heartbeat every 30 s so intermediate proxies
        (HAProxy, mitmproxy, nginx) keep the long-poll connection alive.
        """
        q = self.subscribe()
        # SSE comments — browsers + EventSource ignore lines starting with ":"
        yield ": subscribed\n\n"
        HEARTBEAT_SEC = 30.0
        try:
            while True:
                try:
                    alert = await asyncio.wait_for(q.get(), timeout=HEARTBEAT_SEC)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield "event: alert\ndata: " + json.dumps(asdict(alert)) + "\n\n"
        finally:
            self.unsubscribe(q)
