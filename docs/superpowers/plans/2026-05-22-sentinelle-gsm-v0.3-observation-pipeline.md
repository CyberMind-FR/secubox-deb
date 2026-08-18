<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-sentinelle-gsm v0.3.0 — Passive Observation Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (preferred) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the actual passive GSM observation pipeline. v0.2.x shipped the UI + alert sink + trusted registry but no detection — alerts could only be POSTed manually. v0.3.0 spawns `grgsm_livemon_headless` as a managed subprocess, parses the GSMTAP frames it emits on `127.0.0.1:4729`, persists cell sightings to a SQLite `observations.db`, and exposes the whole flow as a "Scan control" + "Observations" UI.

**Architecture:**

```
Operator clicks "Start scan" in webui
        ↓
POST /api/v1/sensor/gsm/scan/start {freq: "925.4M"}
        ↓
LivemonRunner.start(freq)
   spawns:  grgsm_livemon_headless --args=rtl=0 -f 925.4M
   the CHILD claims the RTL-SDR (parent service never does — closes #344)
   the CHILD emits GSMTAP frames to lo:4729/udp
        ↓
GsmtapListener  (asyncio UDP socket, scapy GSMTAP layer parse)
   yields  Observation(cell_id, arfcn, lac, ci, mcc, mnc, ts, msg_type)
        ↓
ObservationsDB.record(obs)
   UPSERT cell sighting (cell_id PK, sighting_count++, last_seen = now)
   INSERT paging_event row IF msg_type indicates paging request
        ↓
GET /observations  →  webui Observations panel  →  live table
```

**Tech Stack:**
- Python 3.11 / FastAPI
- `asyncio.create_subprocess_exec` for grgsm management
- `scapy` (already in stack; runtime dep)
- SQLite via stdlib
- Existing `Anonymizer` for HMAC of any IMSI/TMSI seen in paging
- Reuse alert_sink's SSE pattern for `/observations/stream` (out of scope for v0.3.0 but the schema is shaped for v0.3.1)

**Privacy invariant (load-bearing):**
- Any IMSI/TMSI seen in a paging request goes through `Anonymizer.anonymize()` BEFORE persistence.
- `observations.db` schema has NO `imsi` / `tmsi` / `imei` plaintext columns — only `subscriber_hash`.
- The privacy invariant test is extended to cover `ObservationsDB` and `Observation` dataclass.

**Out of scope (v0.3.1 and later):**
- Scoring engine fill-in (8 heuristics — needs real-world baseline first)
- Carrier baseline auto-detection (sweep across all ARFCNs)
- Alert emission from observations (currently manual via `/alerts/test`)
- Multi-frequency simultaneous scan (one freq at a time in v0.3.0)
- gr-gsm runtime dep install in postinst (it's already installed on gk2 from earlier validation; CI build doesn't need it)

---

## File Structure

- **Create:**
  - `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/livemon_runner.py`
  - `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/gsmtap_listener.py`
  - `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/observations.py`
  - `packages/secubox-sentinelle-gsm/api/tests/test_livemon_runner.py`
  - `packages/secubox-sentinelle-gsm/api/tests/test_gsmtap_listener.py`
  - `packages/secubox-sentinelle-gsm/api/tests/test_observations.py`
  - `packages/secubox-sentinelle-gsm/api/tests/test_scan_api.py`
- **Modify:**
  - `packages/secubox-sentinelle-gsm/api/main.py` — `/scan/{start,stop,status}` + `/observations` + startup wiring
  - `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/livemon.py` — DELETE the v0.1 USB-detect stub (replaced by `livemon_runner.py`). DO NOT REINTRODUCE any startup-time USB claim — that's the #344 bug.
  - `packages/secubox-sentinelle-gsm/www/sentinelle/index.html` + `sentinelle.css` + `sentinelle.js` — new "Scan control" + "Observations" panels
  - `packages/secubox-sentinelle-gsm/debian/control` — add `python3-scapy` to Depends (if not already; check first)
  - `packages/secubox-sentinelle-gsm/debian/postinst` — state dir `/var/lib/secubox/sentinelle-gsm/observations.db`
  - `packages/secubox-sentinelle-gsm/tests/test_privacy_invariant.py` — extend to cover Observation + ObservationsDB
  - `packages/secubox-sentinelle-gsm/debian/changelog` — bump to 0.3.0

---

## Task 1 — `livemon_runner.py` (subprocess spawn/kill)

**Files:**
- Create: `lib/sentinelle_gsm/livemon_runner.py`
- Create: `api/tests/test_livemon_runner.py`

The runner manages a single `grgsm_livemon_headless` subprocess at a time. It owns the device claim lifecycle: only the child process holds the RTL-SDR, the parent never. This is what closes #344.

- [ ] **Step 1: Write `livemon_runner.py`**

```python
# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/livemon_runner.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

"""
Manages the lifecycle of a single grgsm_livemon_headless subprocess.

Key design point (closes #344): the parent service NEVER opens the
RTL-SDR directly. Only the child grgsm_livemon_headless process claims
the device; when stopped, it releases. This lets ad-hoc tools
(rtl_test, rtl_adsb, kalibrate) coexist with the service when no scan
is active.
"""

from __future__ import annotations

import asyncio
import dataclasses
import shutil
import time
from typing import Optional


@dataclasses.dataclass
class ScanStatus:
    running: bool = False
    pid: Optional[int] = None
    freq: Optional[str] = None
    started_at: Optional[float] = None
    stderr_tail: str = ""


class LivemonRunner:
    def __init__(self, gsmtap_port: int = 4729):
        self.gsmtap_port = gsmtap_port
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._freq: Optional[str] = None
        self._started_at: Optional[float] = None
        self._stderr_buf = bytearray()
        self._stderr_task: Optional[asyncio.Task] = None
        self._bin = shutil.which("grgsm_livemon_headless") or "/usr/bin/grgsm_livemon_headless"

    def status(self) -> ScanStatus:
        running = self._proc is not None and self._proc.returncode is None
        return ScanStatus(
            running=running,
            pid=self._proc.pid if running else None,
            freq=self._freq if running else None,
            started_at=self._started_at if running else None,
            stderr_tail=self._stderr_buf.decode(errors="replace")[-2000:],
        )

    async def start(self, freq: str) -> ScanStatus:
        """Spawn grgsm_livemon_headless on the given frequency.

        freq: anything grgsm_livemon_headless accepts, e.g. '925.4M', '947.4e6'.
        """
        if self._proc is not None and self._proc.returncode is None:
            raise RuntimeError("scan already running — stop first")

        # gr-osmosdr default device is UHD; force RTL-SDR via --args=rtl=0
        self._proc = await asyncio.create_subprocess_exec(
            self._bin,
            "--args=rtl=0",
            "-f", freq,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self._freq = freq
        self._started_at = time.time()
        self._stderr_buf = bytearray()
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        return self.status()

    async def stop(self, timeout: float = 5.0) -> ScanStatus:
        """SIGTERM the child; SIGKILL if it doesn't exit within timeout."""
        if self._proc is None or self._proc.returncode is not None:
            return self.status()
        self._proc.terminate()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self._proc.kill()
            await self._proc.wait()
        if self._stderr_task:
            self._stderr_task.cancel()
        self._proc = None
        self._freq = None
        self._started_at = None
        return self.status()

    async def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        try:
            while True:
                chunk = await self._proc.stderr.read(4096)
                if not chunk:
                    break
                self._stderr_buf.extend(chunk)
                # Cap to last 16 KiB to bound memory.
                if len(self._stderr_buf) > 16384:
                    del self._stderr_buf[:-16384]
        except asyncio.CancelledError:
            pass
```

- [ ] **Step 2: Write tests with mocked subprocess**

```python
# packages/secubox-sentinelle-gsm/api/tests/test_livemon_runner.py
import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sentinelle_gsm.livemon_runner import LivemonRunner, ScanStatus


@pytest.mark.asyncio
async def test_initial_status_not_running():
    r = LivemonRunner()
    s = r.status()
    assert s.running is False
    assert s.pid is None


@pytest.mark.asyncio
async def test_start_spawns_with_rtl_args():
    r = LivemonRunner()
    fake_proc = MagicMock(spec=asyncio.subprocess.Process)
    fake_proc.pid = 12345
    fake_proc.returncode = None
    fake_proc.stderr = AsyncMock()
    fake_proc.stderr.read = AsyncMock(return_value=b"")
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)) as mck:
        s = await r.start("925.4M")
    args = mck.call_args[0]
    assert "--args=rtl=0" in args
    assert "-f" in args and "925.4M" in args
    assert s.running is True
    assert s.pid == 12345


@pytest.mark.asyncio
async def test_start_refuses_double_start():
    r = LivemonRunner()
    fake_proc = MagicMock(); fake_proc.pid = 12345; fake_proc.returncode = None
    fake_proc.stderr = AsyncMock(); fake_proc.stderr.read = AsyncMock(return_value=b"")
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)):
        await r.start("925.4M")
        with pytest.raises(RuntimeError, match="already running"):
            await r.start("947.4M")


@pytest.mark.asyncio
async def test_stop_sends_sigterm_then_clears_state():
    r = LivemonRunner()
    fake_proc = MagicMock(); fake_proc.pid = 12345; fake_proc.returncode = None
    fake_proc.stderr = AsyncMock(); fake_proc.stderr.read = AsyncMock(return_value=b"")
    fake_proc.terminate = MagicMock()
    fake_proc.wait = AsyncMock(return_value=0)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)):
        await r.start("925.4M")
        s = await r.stop()
    fake_proc.terminate.assert_called_once()
    assert s.running is False


@pytest.mark.asyncio
async def test_stop_when_not_running_is_noop():
    r = LivemonRunner()
    s = await r.stop()
    assert s.running is False
```

- [ ] **Step 3: Run + commit**

```bash
cd packages/secubox-sentinelle-gsm
python3 -m pytest api/tests/test_livemon_runner.py -v
```
Expected: 5 passed.

```bash
git add packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/livemon_runner.py \
        packages/secubox-sentinelle-gsm/api/tests/test_livemon_runner.py
git commit -m "feat(sentinelle-gsm): livemon_runner — managed grgsm subprocess (closes #344 ref #347)"
```

---

## Task 2 — `gsmtap_listener.py` (UDP 4729 + scapy parse)

**Files:**
- Create: `lib/sentinelle_gsm/gsmtap_listener.py`
- Create: `api/tests/test_gsmtap_listener.py`

GSMTAP is a thin pseudo-header that grgsm wraps around each demodulated GSM frame and ships via UDP. We listen, parse, and yield typed `Observation` objects to the caller.

- [ ] **Step 1: Confirm scapy availability**

```bash
python3 -c "from scapy.layers.gsmtap import GSMTAP; print('scapy GSMTAP OK')"
apt-cache madison python3-scapy 2>&1 | head -2
```
- If `python3-scapy` is in bookworm (it is, 2.5+) → add it to `debian/control` Depends.
- If not in bookworm — STOP and report; we'll vendor scapy's GSMTAP layer or write a tiny by-hand parser.

- [ ] **Step 2: Write `gsmtap_listener.py`**

```python
# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/gsmtap_listener.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

"""
Async UDP listener for GSMTAP frames emitted by grgsm_livemon_headless.

Yields typed Observation events upstream. Privacy: any IMSI/TMSI
detected in the parsed L3 payload is HMAC-hashed via Anonymizer
BEFORE being placed in the Observation; no plaintext subscriber ID
ever crosses this module's API surface.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from typing import AsyncIterator, Optional


GSMTAP_TYPE_UM   = 0x01   # GSM Um frame
GSMTAP_TYPE_ABIS = 0x02
GSMTAP_CHANNEL_BCCH = 0x01
GSMTAP_CHANNEL_CCCH = 0x04


@dataclasses.dataclass
class Observation:
    ts: float
    arfcn: int
    frame_nr: int
    channel: int           # GSMTAP channel type
    sub_type: int          # GSMTAP sub_type
    lac: Optional[int] = None
    ci:  Optional[int]  = None
    mcc: Optional[int]  = None
    mnc: Optional[int]  = None
    cell_id: Optional[str] = None   # canonical "MCC-MNC-LAC-CI"
    subscriber_hash: Optional[str] = None   # HMAC-trunc, NEVER plaintext


def _parse_gsmtap_header(buf: bytes) -> Optional[dict]:
    """Tiny manual GSMTAP v2 header parser (16 bytes fixed).

    Saves us a runtime scapy dep for the hot path; we only use scapy
    for the deep L3 decode (BCCH info, paging requests) where it
    actually carries its weight.
    """
    if len(buf) < 16 or buf[0] != 0x02:           # version 2
        return None
    hdr_len_x4 = buf[1] * 4
    if hdr_len_x4 < 16:
        return None
    return {
        "version":   buf[0],
        "hdr_len":   hdr_len_x4,
        "payload_type": buf[2],
        "timeslot":  buf[3],
        "arfcn":     ((buf[4] & 0x3F) << 8) | buf[5],
        "signal_dbm": buf[6] - 256 if buf[6] > 127 else buf[6],
        "snr_db":    buf[7] - 256 if buf[7] > 127 else buf[7],
        "frame_nr":  int.from_bytes(buf[8:12], "big"),
        "channel":   buf[12],
        "antenna":   buf[13],
        "sub_type":  buf[14],
    }


class GsmtapListener:
    def __init__(self, host: str = "127.0.0.1", port: int = 4729):
        self.host = host
        self.port = port
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._queue: asyncio.Queue[Observation] = asyncio.Queue(maxsize=2048)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _GsmtapProtocol(self._on_datagram),
            local_addr=(self.host, self.port),
            reuse_port=False,
        )

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def _on_datagram(self, data: bytes) -> None:
        hdr = _parse_gsmtap_header(data)
        if hdr is None:
            return
        obs = Observation(
            ts=time.time(),
            arfcn=hdr["arfcn"],
            frame_nr=hdr["frame_nr"],
            channel=hdr["channel"],
            sub_type=hdr["sub_type"],
        )
        # L3 decode (BCCH System Information, CCCH paging) is deferred
        # to v0.3.1 where we wire scapy + the BCCH parser. For v0.3.0
        # we record the bare ARFCN/frame_nr/channel to prove the pipe
        # works and let the operator see real-time activity counts.
        try:
            self._queue.put_nowait(obs)
        except asyncio.QueueFull:
            pass    # drop on overflow; observations are stochastic anyway

    async def observations(self) -> AsyncIterator[Observation]:
        while True:
            yield await self._queue.get()


class _GsmtapProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback):
        self._callback = callback

    def datagram_received(self, data: bytes, addr) -> None:
        self._callback(data)
```

- [ ] **Step 3: Tests with synthetic GSMTAP datagrams**

```python
# packages/secubox-sentinelle-gsm/api/tests/test_gsmtap_listener.py
import asyncio
import socket
import struct
import pytest
from sentinelle_gsm.gsmtap_listener import GsmtapListener, _parse_gsmtap_header


def _build_gsmtap_v2(arfcn: int = 124, frame_nr: int = 0xABCDEF,
                    channel: int = 0x01) -> bytes:
    """Minimal valid GSMTAP v2 16-byte header + empty payload."""
    return struct.pack(
        ">BBBBHbbIBBBB",
        0x02,                  # version
        4,                     # hdr_len/4
        0x01,                  # payload_type = Um
        0,                     # timeslot
        arfcn,                 # arfcn
        -85,                   # signal_dbm
        20,                    # snr_db
        frame_nr,              # frame_nr (u32 BE)
        channel,               # channel
        0,                     # antenna
        0,                     # sub_type
        0,                     # reserved
    )


def test_parse_header_minimum_valid():
    buf = _build_gsmtap_v2(arfcn=124, frame_nr=0x12345, channel=0x04)
    hdr = _parse_gsmtap_header(buf)
    assert hdr is not None
    assert hdr["arfcn"] == 124
    assert hdr["frame_nr"] == 0x12345
    assert hdr["channel"] == 0x04


def test_parse_header_rejects_too_short():
    assert _parse_gsmtap_header(b"\x02\x04\x01\x00") is None


def test_parse_header_rejects_wrong_version():
    buf = bytearray(_build_gsmtap_v2())
    buf[0] = 0x01      # wrong version
    assert _parse_gsmtap_header(bytes(buf)) is None


@pytest.mark.asyncio
async def test_listener_receives_a_datagram(tmp_path):
    # Use a high local port to avoid colliding with a running grgsm.
    listener = GsmtapListener(host="127.0.0.1", port=47291)
    await listener.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(_build_gsmtap_v2(arfcn=42, channel=0x04), ("127.0.0.1", 47291))

        async def first():
            async for obs in listener.observations():
                return obs
        obs = await asyncio.wait_for(first(), timeout=1.0)
        assert obs.arfcn == 42
        assert obs.channel == 0x04
    finally:
        await listener.stop()
```

- [ ] **Step 4: Run + commit**

```bash
cd packages/secubox-sentinelle-gsm
python3 -m pytest api/tests/test_gsmtap_listener.py -v
```

```bash
git commit -am "feat(sentinelle-gsm): gsmtap_listener — async UDP 4729 + GSMTAP v2 parse (ref #347)"
```

---

## Task 3 — `observations.py` (SQLite cell sightings DB)

**Files:**
- Create: `lib/sentinelle_gsm/observations.py`
- Create: `api/tests/test_observations.py`

Persist sightings. Upsert by `cell_id` (deduplicated MCC-MNC-LAC-CI compound key), bump `sighting_count`, track `first_seen` / `last_seen`. Separate `paging_events` table for v0.3.1's hash-matching against `trusted_phones`.

- [ ] **Step 1: Write `observations.py`**

```python
# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/observations.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

"""
SQLite-backed cell sightings + paging events store.

Privacy invariant: paging_events stores ONLY subscriber_hash (HMAC),
never plaintext IMSI/TMSI/IMEI. Enforced by a WRITE-time shape check
identical to the one in alert_sink.
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


_PLAINTEXT_IMSI_RE = re.compile(r"\b\d{15}\b")


@dataclass
class Sighting:
    cell_id: str
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    lac: Optional[int] = None
    ci: Optional[int] = None
    arfcn: Optional[int] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sighting_count: int = 1


@dataclass
class PagingEvent:
    ts: float
    cell_id: str
    subscriber_hash: str        # HMAC-trunc, NEVER plaintext
    request_type: str           # "paging-tmsi" | "paging-imsi" | "identity-request" | ...


class ObservationsDB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS sightings (
                cell_id TEXT PRIMARY KEY,
                mcc INTEGER, mnc INTEGER, lac INTEGER, ci INTEGER,
                arfcn INTEGER,
                first_seen REAL NOT NULL,
                last_seen  REAL NOT NULL,
                sighting_count INTEGER NOT NULL DEFAULT 1
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS paging_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                cell_id TEXT NOT NULL,
                subscriber_hash TEXT NOT NULL,
                request_type TEXT NOT NULL
            )
        """)
        self._db.execute("CREATE INDEX IF NOT EXISTS pe_ts_idx ON paging_events(ts)")
        self._db.execute("CREATE INDEX IF NOT EXISTS pe_cell_idx ON paging_events(cell_id)")
        self._db.commit()

    def upsert_sighting(self, s: Sighting) -> None:
        self._guard_plaintext(s.cell_id)
        now = time.time()
        cur = self._db.execute(
            "SELECT first_seen, sighting_count FROM sightings WHERE cell_id = ?",
            (s.cell_id,),
        ).fetchone()
        if cur is None:
            self._db.execute(
                "INSERT INTO sightings(cell_id,mcc,mnc,lac,ci,arfcn,first_seen,last_seen,sighting_count) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (s.cell_id, s.mcc, s.mnc, s.lac, s.ci, s.arfcn,
                 now, now, 1),
            )
        else:
            self._db.execute(
                "UPDATE sightings SET last_seen=?, sighting_count=sighting_count+1, "
                "arfcn=COALESCE(?, arfcn), mcc=COALESCE(?, mcc), mnc=COALESCE(?, mnc), "
                "lac=COALESCE(?, lac), ci=COALESCE(?, ci) WHERE cell_id=?",
                (now, s.arfcn, s.mcc, s.mnc, s.lac, s.ci, s.cell_id),
            )
        self._db.commit()

    def record_paging(self, e: PagingEvent) -> None:
        self._guard_plaintext(e.cell_id)
        self._guard_plaintext(e.subscriber_hash)
        self._db.execute(
            "INSERT INTO paging_events(ts,cell_id,subscriber_hash,request_type) VALUES (?,?,?,?)",
            (e.ts, e.cell_id, e.subscriber_hash, e.request_type),
        )
        self._db.commit()

    def sightings(self, limit: int = 200) -> list[Sighting]:
        rows = self._db.execute(
            "SELECT cell_id,mcc,mnc,lac,ci,arfcn,first_seen,last_seen,sighting_count "
            "FROM sightings ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [Sighting(*r) for r in rows]

    def paging_for_cell(self, cell_id: str, limit: int = 100) -> list[PagingEvent]:
        rows = self._db.execute(
            "SELECT ts, cell_id, subscriber_hash, request_type FROM paging_events "
            "WHERE cell_id = ? ORDER BY ts DESC LIMIT ?",
            (cell_id, limit),
        ).fetchall()
        return [PagingEvent(*r) for r in rows]

    def _guard_plaintext(self, value: str) -> None:
        if _PLAINTEXT_IMSI_RE.search(value or ""):
            raise ValueError("observations: plaintext-IMSI shape detected — refusing write")
```

- [ ] **Step 2: Tests**

```python
# packages/secubox-sentinelle-gsm/api/tests/test_observations.py
import pytest
from sentinelle_gsm.observations import ObservationsDB, Sighting, PagingEvent


@pytest.fixture
def db(tmp_path):
    return ObservationsDB(tmp_path / "obs.db")


def test_upsert_new_sighting(db):
    s = Sighting(cell_id="208-01-100-12345", arfcn=124)
    db.upsert_sighting(s)
    out = db.sightings()
    assert len(out) == 1
    assert out[0].cell_id == "208-01-100-12345"
    assert out[0].sighting_count == 1


def test_upsert_bumps_count(db):
    s = Sighting(cell_id="208-01-100-12345", arfcn=124)
    for _ in range(5):
        db.upsert_sighting(s)
    out = db.sightings()
    assert out[0].sighting_count == 5


def test_record_paging_with_hash(db):
    e = PagingEvent(ts=1_700_000_000, cell_id="208-01-100-12345",
                    subscriber_hash="a1b2c3d4e5f6deadbeef0011",
                    request_type="paging-tmsi")
    db.record_paging(e)
    rows = db.paging_for_cell("208-01-100-12345")
    assert len(rows) == 1
    assert rows[0].subscriber_hash.startswith("a1b2")


def test_record_paging_refuses_plaintext_imsi(db):
    e = PagingEvent(ts=1_700_000_000, cell_id="208-01-100-12345",
                    subscriber_hash="208201234567890",  # 15 digits
                    request_type="paging-imsi")
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        db.record_paging(e)
```

- [ ] **Step 3: Run + commit**

```bash
python3 -m pytest api/tests/test_observations.py -v
git commit -am "feat(sentinelle-gsm): observations.py — SQLite sightings + paging_events (ref #347)"
```

---

## Task 4 — API endpoints

**Files:**
- Modify: `api/main.py`
- Create: `api/tests/test_scan_api.py`

Add endpoints:
- `POST /scan/start  {freq}`  → spawn livemon, start gsmtap listener consume loop
- `POST /scan/stop`           → SIGTERM child, stop listener
- `GET  /scan/status`         → current state of LivemonRunner + listener
- `GET  /observations`        → recent sightings, optionally paginated

The consume loop reads from `GsmtapListener.observations()` and writes Sighting rows to ObservationsDB. Runs as an asyncio task started by `/scan/start`, cancelled by `/scan/stop`.

- [ ] **Step 1: Add singletons + startup wiring** in main.py

```python
_livemon: Optional[LivemonRunner] = None
_listener: Optional[GsmtapListener] = None
_obs_db: Optional[ObservationsDB] = None
_consume_task: Optional[asyncio.Task] = None


@app.on_event("startup")
def _v0_3_startup():
    global _livemon, _listener, _obs_db
    _livemon = LivemonRunner()
    _listener = GsmtapListener()
    _obs_db = ObservationsDB(Path("/var/lib/secubox/sentinelle-gsm/observations.db"))
```

- [ ] **Step 2: Add the 4 routes** — see plan body. POST /scan/start launches the listener + consume loop. POST /scan/stop cancels both.

For the cell_id formation: until we have BCCH L3 decode (v0.3.1) we don't know MCC/MNC/LAC/CI, so we synthesise `cell_id = f"arfcn-{obs.arfcn}-ch-{obs.channel}"` as a placeholder. The schema accepts NULL for the operator fields.

- [ ] **Step 3: Tests using monkeypatched LivemonRunner**

```python
# api/tests/test_scan_api.py
from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from api import main as api_main
    from sentinelle_gsm.observations import ObservationsDB
    api_main._obs_db = ObservationsDB(tmp_path / "obs.db")
    api_main._livemon = MagicMock()
    api_main._livemon.start = AsyncMock(return_value=MagicMock(
        running=True, pid=42, freq="925.4M", started_at=1.0, stderr_tail=""))
    api_main._livemon.stop = AsyncMock(return_value=MagicMock(
        running=False, pid=None, freq=None, started_at=None, stderr_tail=""))
    api_main._livemon.status = MagicMock(return_value=MagicMock(
        running=False, pid=None, freq=None, started_at=None, stderr_tail=""))
    api_main.app.dependency_overrides[api_main.require_jwt] = lambda: {"sub": "tester"}
    return TestClient(api_main.app)


def test_scan_start_calls_livemon(client):
    r = client.post("/scan/start", json={"freq": "925.4M"})
    assert r.status_code == 200
    assert r.json()["running"] is True


def test_scan_stop_calls_livemon(client):
    r = client.post("/scan/stop")
    assert r.status_code == 200
    assert r.json()["running"] is False


def test_observations_returns_empty_by_default(client):
    r = client.get("/observations")
    assert r.status_code == 200
    assert r.json()["sightings"] == []
```

- [ ] **Step 4: Run + commit**

```bash
python3 -m pytest api/tests/test_scan_api.py -v
git commit -am "feat(sentinelle-gsm): API — /scan/start /scan/stop /scan/status /observations (ref #347)"
```

---

## Task 5 — WebUI scan control + observations table

**Files:**
- Modify: `www/sentinelle/index.html` + `sentinelle.css` + `sentinelle.js`

New panels :
- **Scan control** — frequency input (default 925.4M = ARFCN 5 GSM 900 DL), `[Start]` + `[Stop]` buttons, status pill, stderr-tail display (collapsed by default), elapsed timer
- **Observations** — live table sorted by `last_seen DESC` with columns: ARFCN, Channel, First seen, Last seen, Sighting count

Add to `els` map + `wireEvents()`:
```js
btnScanStart, btnScanStop, scanFreqInput, scanStatusPill,
observationsTbody, btnRefreshObs
```

Wire `loadObservations()` to GET /observations on init + on button click + every 10 s while a scan is running.

- [ ] **Commit**

```bash
git commit -am "feat(sentinelle-gsm): webui scan control + observations panels (ref #347)"
```

---

## Task 6 — nginx + .install + postinst

**Files:**
- Modify: `nginx/sentinelle-webui.conf` — add nothing (no new SSE endpoint in v0.3.0; observations is plain GET)
- Modify: `debian/postinst` — ensure `/var/lib/secubox/sentinelle-gsm` exists (already does from v0.2.x for alerts.db); add `python3-scapy` to Depends if not there
- Modify: `debian/control` — add `python3-scapy` to Depends, `gr-gsm | grgsm` to Recommends

- [ ] **Step 1: Update debian/control**

```bash
# add to existing Depends line :
Depends: ..., python3-scapy
Recommends: gr-gsm
```

Verify with `apt-cache madison python3-scapy gr-gsm` — both must exist in bookworm.

- [ ] **Step 2: Delete the v0.1 livemon.py stub**

```bash
git rm packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/livemon.py
```
The new `livemon_runner.py` replaces it. Make sure nothing imports `from sentinelle_gsm.livemon` :

```bash
grep -rn "from sentinelle_gsm.livemon import\|import livemon" packages/secubox-sentinelle-gsm/
```
Update any caller. The existing api/main.py + tests should import `livemon_runner` instead.

- [ ] **Commit**

```bash
git commit -am "build(sentinelle-gsm): scapy + gr-gsm deps; drop v0.1 livemon.py stub (ref #347)"
```

---

## Task 7 — Privacy invariant test extension + changelog 0.3.0

**Files:**
- Modify: `tests/test_privacy_invariant.py` — add shape checks for `Observation`, `Sighting`, `PagingEvent` (no plaintext-id fields); add behaviour checks for `ObservationsDB._guard_plaintext`
- Modify: `debian/changelog`

- [ ] **Step 1: Extend the privacy test**

Add :
```python
def test_observation_has_no_plaintext_fields():
    from sentinelle_gsm.gsmtap_listener import Observation
    from dataclasses import fields
    names = {f.name for f in fields(Observation)}
    forbidden = {"imsi","tmsi","imei","msisdn","iccid","subscriber_id"}
    assert names.isdisjoint(forbidden)


def test_paging_event_only_stores_hash():
    from sentinelle_gsm.observations import PagingEvent
    from dataclasses import fields
    names = {f.name for f in fields(PagingEvent)}
    assert "imsi" not in names
    assert "subscriber_hash" in names


def test_observations_db_refuses_plaintext(tmp_path):
    from sentinelle_gsm.observations import ObservationsDB, PagingEvent
    import pytest
    db = ObservationsDB(tmp_path / "obs.db")
    e = PagingEvent(ts=0, cell_id="208-01-100-1",
                    subscriber_hash="208201234567890", request_type="paging-imsi")
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        db.record_paging(e)
```

- [ ] **Step 2: Run the FULL sweep**

```bash
python3 -m pytest api/tests/ tests/ -v 2>&1 | tail -10
```
Expected: 29 (existing) + 5 (Task 1) + 4 (Task 2) + 4 (Task 3) + 3 (Task 4) + 3 (privacy) = ~48 tests passing.

- [ ] **Step 3: Changelog bump**

```text
secubox-sentinelle-gsm (0.3.0-1~bookworm1) bookworm; urgency=medium

  * lib/sentinelle_gsm/livemon_runner.py: NEW — manages a single
    grgsm_livemon_headless subprocess. The CHILD claims the RTL-SDR;
    the parent service never does. Closes #344 (ad-hoc tools — rtl_test,
    rtl_adsb, kalibrate — can now run alongside the service when no
    scan is active).
  * lib/sentinelle_gsm/gsmtap_listener.py: NEW — asyncio UDP 4729
    listener with a tiny by-hand GSMTAP v2 header parser, yields
    typed Observation events. L3 decode (BCCH SI, paging) deferred to
    v0.3.1.
  * lib/sentinelle_gsm/observations.py: NEW — SQLite sightings +
    paging_events with the same plaintext-IMSI shape guard as
    alert_sink.
  * lib/sentinelle_gsm/livemon.py: DROPPED — was the v0.1 USB-detect
    stub that caused #344. Replaced by livemon_runner.py.
  * api/main.py: NEW /scan/start, /scan/stop, /scan/status,
    /observations endpoints.
  * www/sentinelle/: NEW Scan control + Observations panels.
  * debian/control: add python3-scapy (runtime) + gr-gsm (Recommends).
  * tests: 19 new (livemon_runner ×5, gsmtap_listener ×4, observations
    ×4, scan_api ×3, privacy ×3); 48/48 total passing.
  * Closes #344. Refs #347. Scoring engine fill-in + alert emission
    from observations remain v0.3.1 scope.

 -- Gerald Kerma <devel@cybermind.fr>  Fri, 22 May 2026 15:30:00 +0000
```

- [ ] **Step 4: Commit**

```bash
git commit -am "chore(sentinelle-gsm): bump 0.3.0 + extend privacy invariant tests (closes #344 #347)"
```

---

## Task 8 — Build + open PR

```bash
cd packages/secubox-sentinelle-gsm
dpkg-buildpackage -us -uc -b 2>&1 | tail -10
```

Check the .deb contains the new modules :

```bash
dpkg-deb -c packages/secubox-sentinelle-gsm_0.3.0-1~bookworm1_all.deb 2>/dev/null | \
  grep -E "livemon_runner|gsmtap_listener|observations\.py"
```

Push branch + open PR with the standard body (closes #344 #347, lists commits, test plan).

---

## Task 9 — On-board E2E (manual, after PR merge)

1. Deploy 0.3.0 .deb to gk2 with `--force-confnew`.
2. Verify `systemctl is-active secubox-sentinelle-gsm` → active.
3. Verify `rtl_test` from a SEPARATE ssh session **WORKS** while service is up (this is the #344 close).
4. POST `/scan/start {"freq": "925.4M"}` → response `running: true, pid: N`.
5. Verify `rtl_test` from a separate session now FAILS with LIBUSB_BUSY (child claims the device).
6. Wait 30 s. Open /sentinelle/, "Observations" panel populated with sightings (one per ARFCN+channel that grgsm sees).
7. POST `/scan/stop` → response `running: false`.
8. `rtl_test` works again.
9. Comment on #347 with "v0.3.0 validated on gk2, closing #344 + #347". Close.
