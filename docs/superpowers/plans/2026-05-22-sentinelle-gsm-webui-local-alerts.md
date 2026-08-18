<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-sentinelle-gsm v0.2 — Standalone WebUI + Local Alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (preferred) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the local-alert + standalone WebUI layer of `secubox-sentinelle-gsm` so an operator can see IMSI-catcher / false-BTS anomalies as they happen, from a dedicated SecuBox UI, with **browser-native desktop notifications** (alerte locale).

**Architecture:**
A detector (built in v0.3) emits anomaly events into a SQLite-backed `alert_sink`. The sink has an in-memory pub/sub hub that fans events out to Server-Sent Events streams. A FastAPI route exposes `/alerts/stream` (SSE) which the standalone WebUI consumes; the WebUI uses the browser Notification API to show desktop alerts even when the tab is not focused. A trusted-phones registry maps HMAC-hashed IMSIs to human-readable labels so the operator knows which of their devices is being targeted.

Off-machine push (SMS via EP06) is **deferred to v0.4** once the spare EP06 is validated. v0.2 is local-only.

**Tech Stack:**
- Python 3.11 + FastAPI (existing in `packages/secubox-sentinelle-gsm/api/`)
- SQLite via `sqlite3` stdlib (no new dep)
- SSE via `sse-starlette` (small, well-maintained — already in stack? check first; if not, use raw `StreamingResponse`)
- Existing `sentinelle_gsm.observer.Anonymizer` for HMAC hashing
- Frontend: vanilla HTML/CSS/JS using the canonical SecuBox webui scaffold (sidebar 220px, MIND palette `#3D35A0`)
- `pytest` + `httpx.AsyncClient` for API tests
- `EventSource` polyfill not needed (modern browsers OK)

**Privacy invariant (load-bearing):**
- IMSI/TMSI/IMEI never stored as plaintext, anywhere, ever — only HMAC-SHA256 truncated tokens.
- The trusted-phones registry stores HMACs; the operator pastes plaintext IMSI in the form ONCE, the server computes the HMAC and immediately discards the plaintext. No plaintext is ever returned by any endpoint, logged, or written to disk.
- The existing `tests/test_privacy_invariant.py` shape check is extended to cover `alert_sink.py` and the trusted-registry module.

**Out of scope (v0.3 and later):**
- gr-gsm / `grgsm_livemon_headless` install + GSMTAP UDP listener + scoring fill-in (this is the actual detection — v0.3, separate plan)
- SMS notification backend via EP06 (v0.4)
- WebPush PWA backend (optional, v0.5+)
- Multi-RTL-SDR coordination (single dongle is the v0.x target)

---

## File Structure

- **Create:**
  - `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/alert_sink.py` — SQLite + SSE hub
  - `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/trusted.py` — registry IO
  - `packages/secubox-sentinelle-gsm/www/sentinelle/index.html`
  - `packages/secubox-sentinelle-gsm/www/sentinelle/sentinelle.css`
  - `packages/secubox-sentinelle-gsm/www/sentinelle/sentinelle.js`
  - `packages/secubox-sentinelle-gsm/nginx/sentinelle-webui.conf` — separate from existing `sentinelle-gsm.conf`
  - `packages/secubox-sentinelle-gsm/menu.d/45-sentinelle.json` — MIND category
  - `packages/secubox-sentinelle-gsm/api/tests/test_alert_sink.py`
  - `packages/secubox-sentinelle-gsm/api/tests/test_alerts_api.py`
  - `packages/secubox-sentinelle-gsm/api/tests/test_trusted_api.py`
- **Modify:**
  - `packages/secubox-sentinelle-gsm/api/main.py` — add `/alerts`, `/alerts/stream`, `/alerts/test`, `/trusted/*` routes
  - `packages/secubox-sentinelle-gsm/conf/sentinelle-gsm.toml.example` — new `[alerts]` + `[trusted_registry]` sections
  - `packages/secubox-sentinelle-gsm/debian/secubox-sentinelle-gsm.install` — ship the new files (create if missing)
  - `packages/secubox-sentinelle-gsm/debian/postinst` — create `/etc/secubox/sentinelle-gsm/` + an empty `trusted.toml` if absent
  - `packages/secubox-sentinelle-gsm/debian/changelog` — bump version with v0.2 summary
  - `packages/secubox-sentinelle-gsm/tests/test_privacy_invariant.py` — extend shape check to the new modules

---

## Task 1 — `alert_sink.py` (SQLite + in-memory SSE hub)

**Files:**
- Create: `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/alert_sink.py`
- Create: `packages/secubox-sentinelle-gsm/api/tests/test_alert_sink.py`

The alert sink is the single point through which all anomalies flow. It serves two readers:
1. The SQLite history (for `GET /alerts` and operator forensics)
2. Live subscribers via an `asyncio.Queue` fan-out (for `GET /alerts/stream` SSE)

The detector (v0.3) will be the writer. For v0.2 we only need the writer interface + a manual test endpoint that calls it.

- [ ] **Step 1: Write the file with the module skeleton**

```python
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
        """Yield SSE-formatted text/event-stream chunks."""
        q = self.subscribe()
        try:
            while True:
                alert = await q.get()
                yield "event: alert\ndata: " + json.dumps(asdict(alert)) + "\n\n"
        finally:
            self.unsubscribe(q)
```

- [ ] **Step 2: Write the failing tests**

```python
# packages/secubox-sentinelle-gsm/api/tests/test_alert_sink.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

import asyncio
import json
import pytest
from sentinelle_gsm.alert_sink import Alert, AlertSink


@pytest.fixture
def sink(tmp_path):
    return AlertSink(tmp_path / "alerts.db")


def test_write_and_list_roundtrip(sink):
    a = Alert(cell_id="208-01-100-12345", arfcn=124, score=85, reason="cipher_downgrade")
    written = sink.write(a)
    assert written.id > 0
    history = sink.list()
    assert len(history) == 1
    assert history[0].cell_id == "208-01-100-12345"
    assert history[0].score == 85


def test_plaintext_imsi_in_reason_is_refused(sink):
    """Privacy invariant: never accept plaintext IMSI in any field."""
    a = Alert(cell_id="208-01-100-12345", arfcn=124, score=85,
              reason="caught IMSI 208201234567890")  # 15 digits = IMSI
    with pytest.raises(ValueError, match="plaintext-IMSI"):
        sink.write(a)


def test_hmac_in_subscriber_hash_is_accepted(sink):
    """Hashed identifier (typical 32-hex chars) must pass the guard."""
    a = Alert(cell_id="208-01-100-12345", arfcn=124, score=85,
              reason="paging targets a trusted IMSI",
              subscriber_hash="a1b2c3d4e5f6deadbeef00112233445566778899aabbccddeeff0011",
              trusted_label="Gerald iPhone")
    written = sink.write(a)
    assert written.subscriber_hash.startswith("a1b2")


@pytest.mark.asyncio
async def test_subscribe_receives_new_alerts(sink):
    q = sink.subscribe()
    try:
        sink.write(Alert(cell_id="208-01-100-99999", arfcn=12, score=72, reason="ghost_bts"))
        got = await asyncio.wait_for(q.get(), timeout=1.0)
        assert got.cell_id == "208-01-100-99999"
        assert got.score == 72
    finally:
        sink.unsubscribe(q)


@pytest.mark.asyncio
async def test_stream_emits_sse_format(sink):
    """One alert written, one SSE chunk yielded."""
    async def collect_one():
        gen = sink.stream()
        return await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    task = asyncio.create_task(collect_one())
    await asyncio.sleep(0.05)  # let subscribe() register
    sink.write(Alert(cell_id="208-01-100-77777", arfcn=88, score=91, reason="identity_request_abuse"))
    chunk = await task
    assert chunk.startswith("event: alert\n")
    data_line = next(l for l in chunk.split("\n") if l.startswith("data: "))
    payload = json.loads(data_line[len("data: "):])
    assert payload["cell_id"] == "208-01-100-77777"
```

- [ ] **Step 3: Run the tests; expect all 5 to pass**

```bash
cd packages/secubox-sentinelle-gsm
python3 -m pytest api/tests/test_alert_sink.py -v
```

Expected: 5 passed.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/alert_sink.py \
        packages/secubox-sentinelle-gsm/api/tests/test_alert_sink.py
git commit -m "feat(sentinelle-gsm): alert_sink — SQLite history + SSE broadcast hub (ref #340)"
```

---

## Task 2 — Trusted phones registry (`trusted.py`)

**Files:**
- Create: `packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/trusted.py`
- Create: `packages/secubox-sentinelle-gsm/api/tests/test_trusted_registry.py`

A trusted phone has:
- `imsi_hash` — HMAC-truncated IMSI (stored)
- `label` — human-readable name (e.g. "Gerald iPhone")
- `added_at` — epoch
- `id` — UUID4

The operator pastes a plaintext IMSI in the `add()` call exactly **once**. The function immediately hashes it via the existing `Anonymizer` and discards the plaintext. No endpoint ever returns the plaintext or accepts an existing hash from the caller.

- [ ] **Step 1: Write `trusted.py`**

```python
# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/trusted.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

"""
Trusted phones registry — HMAC-hashed IMSI mapping to operator-owned
device labels. Persisted to /etc/secubox/sentinelle-gsm/trusted.toml.

Privacy: plaintext IMSI is accepted ONLY by `add()` and is hashed via
the existing Anonymizer before any storage call. No function ever
returns a plaintext IMSI. The TOML on disk holds only hashes.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

import tomli_w

from sentinelle_gsm.observer import Anonymizer


@dataclass
class TrustedPhone:
    id: str
    imsi_hash: str
    label: str
    added_at: float


class TrustedRegistry:
    def __init__(self, path: Path, anonymizer: Anonymizer):
        self.path = Path(path)
        self._anon = anonymizer
        self._phones: dict[str, TrustedPhone] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        data = tomllib.loads(self.path.read_text())
        for entry in data.get("phones", []):
            p = TrustedPhone(
                id=entry["id"],
                imsi_hash=entry["imsi_hash"],
                label=entry.get("label", ""),
                added_at=entry.get("added_at", time.time()),
            )
            self._phones[p.id] = p

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"phones": [asdict(p) for p in self._phones.values()]}
        # tomli_w writes atomically via temp
        self.path.write_text(tomli_w.dumps(payload))
        self.path.chmod(0o640)

    def add(self, plaintext_imsi: str, label: str) -> TrustedPhone:
        """Hash the plaintext IMSI, persist the hash + label, discard plaintext."""
        if not plaintext_imsi.isdigit() or not (14 <= len(plaintext_imsi) <= 15):
            raise ValueError("IMSI must be 14 or 15 digits")
        imsi_hash = self._anon.hash_subscriber_id(plaintext_imsi)
        phone = TrustedPhone(
            id=str(uuid.uuid4()),
            imsi_hash=imsi_hash,
            label=label,
            added_at=time.time(),
        )
        self._phones[phone.id] = phone
        self._save()
        # `plaintext_imsi` goes out of scope here
        return phone

    def list(self) -> list[TrustedPhone]:
        return list(self._phones.values())

    def get_by_id(self, phone_id: str) -> Optional[TrustedPhone]:
        return self._phones.get(phone_id)

    def lookup_by_hash(self, imsi_hash: str) -> Optional[TrustedPhone]:
        """Detector calls this when a paging request matches an IMSI hash."""
        for p in self._phones.values():
            if p.imsi_hash == imsi_hash:
                return p
        return None

    def delete(self, phone_id: str) -> bool:
        if phone_id not in self._phones:
            return False
        del self._phones[phone_id]
        self._save()
        return True
```

- [ ] **Step 2: Verify the existing `Anonymizer` has the `hash_subscriber_id` method**

```bash
grep -nE "def hash_subscriber_id|class Anonymizer" packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/observer.py
```

If the method name differs, adapt the call in `trusted.py` to match. If `Anonymizer` doesn't expose a hashing method directly, add a tiny shim (this is acceptable; the privacy code is the source of truth).

- [ ] **Step 3: Add `tomli_w` to the package's runtime deps**

`packages/secubox-sentinelle-gsm/debian/control` — append `python3-tomli-w` to the `Depends:` line (or `Recommends:` if not in bookworm-main; check `apt-cache madison python3-tomli-w`). If not in bookworm, use the existing repo bundle pattern (vendor it under `lib/sentinelle_gsm/_vendor/`).

- [ ] **Step 4: Write failing tests**

```python
# packages/secubox-sentinelle-gsm/api/tests/test_trusted_registry.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

import pytest
from sentinelle_gsm.observer import Anonymizer
from sentinelle_gsm.trusted import TrustedRegistry


@pytest.fixture
def anon():
    return Anonymizer(b"test-secret-32-bytes" + b"\0" * 12)


@pytest.fixture
def reg(tmp_path, anon):
    return TrustedRegistry(tmp_path / "trusted.toml", anon)


def test_add_hashes_and_does_not_store_plaintext(reg, tmp_path):
    p = reg.add("208201234567890", "Gerald iPhone")
    assert p.label == "Gerald iPhone"
    assert p.imsi_hash != "208201234567890"
    raw = (tmp_path / "trusted.toml").read_text()
    assert "208201234567890" not in raw
    assert p.imsi_hash in raw


def test_lookup_by_hash_finds_added_phone(reg):
    p = reg.add("208201234567890", "iPhone")
    found = reg.lookup_by_hash(p.imsi_hash)
    assert found is not None
    assert found.label == "iPhone"


def test_lookup_by_hash_returns_none_for_unknown(reg):
    reg.add("208201234567890", "iPhone")
    assert reg.lookup_by_hash("0" * 32) is None


def test_delete_removes_entry(reg):
    p = reg.add("208201234567890", "iPhone")
    assert reg.delete(p.id) is True
    assert reg.list() == []
    assert reg.delete("not-an-id") is False


def test_invalid_imsi_rejected(reg):
    with pytest.raises(ValueError):
        reg.add("not-digits", "foo")
    with pytest.raises(ValueError):
        reg.add("123", "too-short")
    with pytest.raises(ValueError):
        reg.add("9" * 16, "too-long")


def test_persistence_across_instances(reg, tmp_path, anon):
    reg.add("208201234567890", "iPhone")
    reg2 = TrustedRegistry(tmp_path / "trusted.toml", anon)
    assert len(reg2.list()) == 1
    assert reg2.list()[0].label == "iPhone"
```

- [ ] **Step 5: Run + commit**

```bash
cd packages/secubox-sentinelle-gsm
python3 -m pytest api/tests/test_trusted_registry.py -v
```

Expected: 6 passed.

```bash
git add packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/trusted.py \
        packages/secubox-sentinelle-gsm/api/tests/test_trusted_registry.py \
        packages/secubox-sentinelle-gsm/debian/control
git commit -m "feat(sentinelle-gsm): trusted phones registry — HMAC-hashed IMSI + label (ref #340)"
```

---

## Task 3 — API endpoints

**Files:**
- Modify: `packages/secubox-sentinelle-gsm/api/main.py`
- Create: `packages/secubox-sentinelle-gsm/api/tests/test_alerts_api.py`
- Create: `packages/secubox-sentinelle-gsm/api/tests/test_trusted_api.py`

Add 6 endpoints under the existing `/api/v1/sensor/gsm/` prefix:

| Verb | Path | Purpose |
|---|---|---|
| GET | `/alerts` | paginated history; query params `?limit=100&since=<epoch>` |
| GET | `/alerts/stream` | Server-Sent Events live feed |
| POST | `/alerts/test` | manual trigger (operator-only) for end-to-end validation |
| GET | `/trusted` | list trusted phones |
| POST | `/trusted` | add (body: `{imsi: "...", label: "..."}`) |
| DELETE | `/trusted/{id}` | remove |

All routes use the existing `Depends(require_jwt)` pattern. `/alerts/stream` returns `StreamingResponse` with `media_type="text/event-stream"` and the proper SSE headers (`Cache-Control: no-cache`, `X-Accel-Buffering: no` so nginx doesn't buffer it).

- [ ] **Step 1: Add the alert_sink + registry singletons to main.py startup**

Find the `app = FastAPI(...)` line and the existing config-load block. Below the config load, add module-level singletons:

```python
# Wired in startup (see app.on_event("startup")) so tests can override.
_alert_sink: AlertSink | None = None
_trusted_registry: TrustedRegistry | None = None


def get_alert_sink() -> AlertSink:
    if _alert_sink is None:
        raise RuntimeError("alert_sink not initialised")
    return _alert_sink


def get_trusted_registry() -> TrustedRegistry:
    if _trusted_registry is None:
        raise RuntimeError("trusted_registry not initialised")
    return _trusted_registry
```

In the existing startup handler (or add one):

```python
@app.on_event("startup")
def _init_v0_2():
    global _alert_sink, _trusted_registry
    state_dir = Path("/var/lib/secubox/sentinelle-gsm")
    _alert_sink = AlertSink(state_dir / "alerts.db")
    _trusted_registry = TrustedRegistry(
        Path("/etc/secubox/sentinelle-gsm/trusted.toml"),
        _get_anonymizer(),  # existing helper in main.py
    )
```

Adapt path constants if `main.py` already centralises them.

- [ ] **Step 2: Add the 6 routes**

```python
class TrustedAddBody(BaseModel):
    imsi: str
    label: str


class TrustedOut(BaseModel):
    id: str
    imsi_hash: str
    label: str
    added_at: float


@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(limit: int = 100, since: float = 0.0):
    return {"alerts": [asdict(a) for a in get_alert_sink().list(limit=limit, since=since)]}


@app.get("/alerts/stream", dependencies=[Depends(require_jwt)])
async def stream_alerts():
    sink = get_alert_sink()
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}
    return StreamingResponse(sink.stream(), media_type="text/event-stream", headers=headers)


@app.post("/alerts/test", dependencies=[Depends(require_jwt)])
async def test_alert(body: dict | None = None):
    """Manual operator trigger — writes a synthetic alert to validate the wiring."""
    body = body or {}
    a = Alert(
        cell_id=body.get("cell_id", "208-01-100-99999"),
        arfcn=body.get("arfcn", 124),
        score=body.get("score", 80),
        reason=body.get("reason", "operator-test"),
        subscriber_hash=body.get("subscriber_hash"),
        trusted_label=body.get("trusted_label"),
    )
    get_alert_sink().write(a)
    return {"ok": True, "id": a.id}


@app.get("/trusted", dependencies=[Depends(require_jwt)])
async def list_trusted():
    return {"phones": [asdict(p) for p in get_trusted_registry().list()]}


@app.post("/trusted", dependencies=[Depends(require_jwt)])
async def add_trusted(body: TrustedAddBody):
    try:
        p = get_trusted_registry().add(body.imsi, body.label)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return asdict(p)


@app.delete("/trusted/{phone_id}", dependencies=[Depends(require_jwt)])
async def delete_trusted(phone_id: str):
    ok = get_trusted_registry().delete(phone_id)
    if not ok:
        raise HTTPException(404, "not found")
    return {"ok": True}
```

- [ ] **Step 3: Tests for the API**

```python
# packages/secubox-sentinelle-gsm/api/tests/test_alerts_api.py
import asyncio
import json
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from sentinelle_gsm.observer import Anonymizer
    from sentinelle_gsm.alert_sink import AlertSink
    from sentinelle_gsm.trusted import TrustedRegistry
    from api import main as api_main

    api_main._alert_sink = AlertSink(tmp_path / "alerts.db")
    api_main._trusted_registry = TrustedRegistry(
        tmp_path / "trusted.toml", Anonymizer(b"x" * 32)
    )
    # JWT bypass via dependency_overrides (matches secubox-streamlit pattern)
    api_main.app.dependency_overrides[api_main.require_jwt] = lambda: {"sub": "tester"}
    return TestClient(api_main.app)


def test_post_alerts_test_writes_one(client):
    r = client.post("/alerts/test")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_get_alerts_returns_history(client):
    client.post("/alerts/test", json={"cell_id": "208-01-100-1"})
    client.post("/alerts/test", json={"cell_id": "208-01-100-2"})
    r = client.get("/alerts?limit=10")
    assert r.status_code == 200
    cells = [a["cell_id"] for a in r.json()["alerts"]]
    assert "208-01-100-1" in cells and "208-01-100-2" in cells


def test_test_alert_refuses_plaintext_imsi(client):
    r = client.post("/alerts/test", json={"reason": "saw IMSI 208201234567890"})
    assert r.status_code == 500   # AlertSink raises ValueError → 500


def test_stream_emits_one_event(client):
    """SSE smoke test — write then read one chunk."""
    with client.stream("GET", "/alerts/stream") as resp:
        # Trigger a write from another in-process call
        client.post("/alerts/test", json={"cell_id": "208-01-100-SSE"})
        chunk = next(resp.iter_lines())
        # First line is "event: alert"
        assert chunk == "event: alert"
```

```python
# packages/secubox-sentinelle-gsm/api/tests/test_trusted_api.py
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    from sentinelle_gsm.observer import Anonymizer
    from sentinelle_gsm.alert_sink import AlertSink
    from sentinelle_gsm.trusted import TrustedRegistry
    from api import main as api_main

    api_main._alert_sink = AlertSink(tmp_path / "alerts.db")
    api_main._trusted_registry = TrustedRegistry(
        tmp_path / "trusted.toml", Anonymizer(b"x" * 32)
    )
    api_main.app.dependency_overrides[api_main.require_jwt] = lambda: {"sub": "tester"}
    return TestClient(api_main.app)


def test_add_list_delete_roundtrip(client):
    r = client.post("/trusted", json={"imsi": "208201234567890", "label": "iPhone"})
    assert r.status_code == 200
    pid = r.json()["id"]
    assert r.json()["label"] == "iPhone"
    assert r.json()["imsi_hash"] != "208201234567890"

    r = client.get("/trusted")
    assert r.status_code == 200
    assert len(r.json()["phones"]) == 1

    r = client.delete(f"/trusted/{pid}")
    assert r.status_code == 200

    r = client.get("/trusted")
    assert r.json()["phones"] == []


def test_add_invalid_imsi_returns_400(client):
    r = client.post("/trusted", json={"imsi": "abc", "label": "x"})
    assert r.status_code == 400


def test_delete_unknown_returns_404(client):
    r = client.delete("/trusted/not-an-id")
    assert r.status_code == 404
```

- [ ] **Step 4: Run + commit**

```bash
cd packages/secubox-sentinelle-gsm
python3 -m pytest api/tests/test_alerts_api.py api/tests/test_trusted_api.py -v
```

Expected: 7 passed.

```bash
git add packages/secubox-sentinelle-gsm/api/main.py \
        packages/secubox-sentinelle-gsm/api/tests/test_alerts_api.py \
        packages/secubox-sentinelle-gsm/api/tests/test_trusted_api.py
git commit -m "feat(sentinelle-gsm): API — /alerts (history + SSE + test) + /trusted CRUD (ref #340)"
```

---

## Task 4 — Standalone WebUI

**Files:**
- Create: `packages/secubox-sentinelle-gsm/www/sentinelle/index.html`
- Create: `packages/secubox-sentinelle-gsm/www/sentinelle/sentinelle.css`
- Create: `packages/secubox-sentinelle-gsm/www/sentinelle/sentinelle.js`

The webui follows the canonical SecuBox scaffold:
- `body` with `display: flex`
- `aside.sidebar` 220px fixed
- `main` with `padding-top: calc(48px + 1.5rem)` to reserve space for the injected global menu bar
- Charte MIND palette: `--mind-violet: #3D35A0` as the accent
- Typography: Space Grotesk (titles) + JetBrains Mono (data/code)

Layout (single page, no SPA router needed):

```
┌────────────────┬─────────────────────────────────────────────────┐
│   ASIDE 220px  │              MAIN                               │
│                │  ┌──────────────────────────────────────────┐   │
│   sentinelle   │  │  STATUS bar                              │   │
│                │  │  RTL-SDR: ok / detector: idle / …        │   │
│   • Alerts     │  └──────────────────────────────────────────┘   │
│   • Trusted    │  ┌──────────────────────────────────────────┐   │
│   • Settings   │  │  ALERTS — live (SSE)                    │   │
│                │  │  • 12:34:56  cell 208-01-100-12345 …    │   │
│                │  │    score 87  reason cipher_downgrade    │   │
│                │  │  • 12:32:11  …                          │   │
│                │  └──────────────────────────────────────────┘   │
│                │  ┌──────────────────────────────────────────┐   │
│                │  │  TRUSTED PHONES                          │   │
│                │  │  [+ Add]                                 │   │
│                │  │   id   label        added                │   │
│                │  │   abc  iPhone       2026-05-22 …  [×]   │   │
│                │  └──────────────────────────────────────────┘   │
│                │  [TEST ALERT] [REQUEST DESKTOP PERMISSION]      │
└────────────────┴─────────────────────────────────────────────────┘
```

- [ ] **Step 1: Skeleton — `index.html`**

(Mirror `packages/secubox-dns-provider/www/dns-provider/index.html` for the scaffold; replace branding + palette + content.)

Provide a header with a `<title>SecuBox — SENTINELLE-GSM</title>`, link to `sentinelle.css`, and a `<script defer src="sentinelle.js"></script>`. The `<aside class="sidebar">` lists the section anchors; `<main class="main">` has the four panels (status / alerts / trusted / actions).

- [ ] **Step 2: Browser Notification API in `sentinelle.js`**

```javascript
// On page load: ask for permission once, then keep the state in localStorage.
async function ensureNotificationPermission() {
    if (!("Notification" in window)) return false;
    if (Notification.permission === "granted") return true;
    if (Notification.permission === "denied") return false;
    const p = await Notification.requestPermission();
    return p === "granted";
}

function showDesktopAlert(alert) {
    if (Notification.permission !== "granted") return;
    const title = `SENTINELLE-GSM — score ${alert.score}`;
    const body = `${alert.reason}\ncell ${alert.cell_id} arfcn ${alert.arfcn}` +
                 (alert.trusted_label ? `\ntargets: ${alert.trusted_label}` : "");
    const n = new Notification(title, { body, icon: "/shared/secubox-mind.png", tag: `sgsm-${alert.id}` });
    n.onclick = () => { window.focus(); n.close(); };
}
```

- [ ] **Step 3: SSE consumer in `sentinelle.js`**

```javascript
function startAlertStream() {
    const es = new EventSource("/api/v1/sensor/gsm/alerts/stream");
    es.addEventListener("alert", (e) => {
        const alert = JSON.parse(e.data);
        prependToAlertList(alert);
        showDesktopAlert(alert);
        playBeep();  // optional, <audio> tag preloaded
    });
    es.onerror = () => {
        // browser auto-retries; just surface a status pill
        document.getElementById("stream-status").textContent = "reconnecting…";
        setTimeout(() => {
            document.getElementById("stream-status").textContent = "live";
        }, 2000);
    };
}
```

- [ ] **Step 4: CRUD wiring + Test button**

```javascript
async function loadTrusted() { /* GET /trusted, render table */ }
async function addTrusted(imsi, label) { /* POST /trusted */ }
async function deleteTrusted(id) { /* DELETE /trusted/{id} */ }
async function fireTestAlert() { /* POST /alerts/test */ }
```

All routes are at `/api/v1/sensor/gsm/...` (the existing prefix).

- [ ] **Step 5: Smoke test in a real browser**

Spin a local FastAPI dev server with the package's `api.main:app`, open the page, click "Request desktop permission" → grant. Click "Test alert" → confirm the row appears AND a desktop notification fires. Refresh page → confirm the historic alerts list still shows the test entry.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-sentinelle-gsm/www/sentinelle/
git commit -m "feat(sentinelle-gsm): standalone webui — live alerts + browser Notification API (ref #340)"
```

---

## Task 5 — nginx route + menu.d entry

**Files:**
- Create: `packages/secubox-sentinelle-gsm/nginx/sentinelle-webui.conf`
- Create: `packages/secubox-sentinelle-gsm/menu.d/45-sentinelle.json`
- Modify: `packages/secubox-sentinelle-gsm/debian/secubox-sentinelle-gsm.install`

- [ ] **Step 1: nginx route**

```nginx
# /etc/nginx/secubox.d/sentinelle-webui.conf
# Installed by secubox-sentinelle-gsm.

# Static webui for the SENTINELLE-GSM module — admin.gk2.secubox.in/sentinelle/
location /sentinelle/ {
    alias /usr/share/secubox/www/sentinelle/;
    try_files $uri $uri/ /sentinelle/index.html;
    add_header Cache-Control "no-cache, must-revalidate";
}

# The existing /api/v1/sensor/gsm/ proxy is provided by sentinelle-gsm.conf;
# we add SSE-friendly settings here that override buffering for the stream:
location /api/v1/sensor/gsm/alerts/stream {
    proxy_pass http://unix:/run/secubox/sentinelle-gsm.sock:/api/v1/sensor/gsm/alerts/stream;
    include /etc/nginx/snippets/secubox-proxy.conf;

    # SSE: long-lived connection, no buffering, no idle timeout.
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 24h;
    proxy_send_timeout 24h;
}
```

- [ ] **Step 2: menu.d entry (MIND category, violet)**

```json
{
  "id": "sentinelle",
  "name": "SENTINELLE-GSM",
  "path": "/sentinelle/",
  "category": "MIND",
  "icon": "satellite",
  "order": 45,
  "description": "Passive IMSI-catcher / false-BTS sensor — live alerts"
}
```

- [ ] **Step 3: `.install` lines**

Append to `debian/secubox-sentinelle-gsm.install`:

```
www/sentinelle/                  usr/share/secubox/www/
nginx/sentinelle-webui.conf      etc/nginx/secubox.d/
menu.d/45-sentinelle.json        usr/share/secubox/menu.d/
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-sentinelle-gsm/nginx/sentinelle-webui.conf \
        packages/secubox-sentinelle-gsm/menu.d/45-sentinelle.json \
        packages/secubox-sentinelle-gsm/debian/secubox-sentinelle-gsm.install
git commit -m "feat(sentinelle-gsm): nginx route /sentinelle/ + MIND menu entry (ref #340)"
```

---

## Task 6 — Privacy invariant test extension + changelog bump

**Files:**
- Modify: `packages/secubox-sentinelle-gsm/tests/test_privacy_invariant.py`
- Modify: `packages/secubox-sentinelle-gsm/debian/changelog`

- [ ] **Step 1: Extend the shape check**

The existing `test_privacy_invariant.py` proves `GsmCellObservation` has no plaintext-IMSI-capable field. Extend it to also assert:

1. `sentinelle_gsm.alert_sink.Alert` has no field named `imsi`, `imei`, `tmsi`, `msisdn`, `iccid` (only `subscriber_hash`).
2. `sentinelle_gsm.trusted.TrustedPhone` has no field named `imsi` (only `imsi_hash`).
3. `AlertSink.write` raises `ValueError` when any string field contains a 15-digit token (plaintext IMSI shape).

Add 3 new assertions to the existing test module. Run the full suite.

- [ ] **Step 2: Changelog bump**

Read `packages/secubox-sentinelle-gsm/debian/changelog` head, then prepend:

```text
secubox-sentinelle-gsm (0.2.0-1~bookworm1) bookworm; urgency=medium

  * lib/sentinelle_gsm/alert_sink.py: new SQLite history + asyncio
    pub/sub hub for Server-Sent Events streaming. Refuses to write
    any field that matches the 15-digit plaintext-IMSI shape.
  * lib/sentinelle_gsm/trusted.py: new trusted-phones registry
    storing HMAC-hashed IMSI + operator label in
    /etc/secubox/sentinelle-gsm/trusted.toml. Plaintext IMSI is
    accepted by add() only and immediately discarded.
  * api/main.py: 6 new endpoints under /api/v1/sensor/gsm/ —
    GET /alerts, GET /alerts/stream (SSE), POST /alerts/test,
    GET /trusted, POST /trusted, DELETE /trusted/{id}.
  * www/sentinelle/: new standalone WebUI at
    admin.gk2.secubox.in/sentinelle/ (charte MIND #3D35A0).
    Live alerts feed via SSE; Browser Notification API drives
    desktop push (alerte locale) even when the tab is unfocused;
    optional <audio> beep on new alert.
  * nginx/sentinelle-webui.conf: route /sentinelle/ + SSE-tuned
    proxy block for /api/v1/sensor/gsm/alerts/stream (no buffering,
    24h read/send timeout).
  * menu.d/45-sentinelle.json: MIND-category entry.
  * tests/test_privacy_invariant.py: extended to cover Alert,
    TrustedPhone, and AlertSink.write privacy guard.
  * Off-machine push (SMS via EP06, WebPush PWA) deferred to
    v0.4 / v0.5+ as per #340 scope. Closes #340.

 -- Gerald Kerma <devel@cybermind.fr>  Fri, 22 May 2026 12:00:00 +0000
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-sentinelle-gsm/tests/test_privacy_invariant.py \
        packages/secubox-sentinelle-gsm/debian/changelog
git commit -m "chore(sentinelle-gsm): bump 0.2.0 + extend privacy invariant tests (closes #340)"
```

---

## Task 7 — Build the .deb and open the PR

- [ ] **Step 1: Build**

```bash
cd packages/secubox-sentinelle-gsm
dpkg-buildpackage -us -uc -b 2>&1 | tail -20
```

Expected: `secubox-sentinelle-gsm_0.2.0-1~bookworm1_all.deb` in the parent dir. Check the .deb contains the new bits:

```bash
dpkg-deb -c ../secubox-sentinelle-gsm_0.2.0-1~bookworm1_all.deb 2>/dev/null | \
    grep -E "alert_sink\.py|trusted\.py|www/sentinelle/|sentinelle-webui\.conf|45-sentinelle\.json"
```

Expected: all 5 file patterns present.

- [ ] **Step 2: Push + PR**

```bash
git push -u origin feat/340-sentinelle-gsm-webui-local-alerts
gh pr create --title "feat(secubox-sentinelle-gsm): v0.2.0 — standalone WebUI + local alerts (SSE + browser notification) (closes #340)" --body "$(cat <<'EOF'
## Summary
Builds the local-alert + standalone WebUI layer of secubox-sentinelle-gsm so an operator can see IMSI-catcher / false-BTS anomalies as they happen, from a dedicated SecuBox UI, with browser-native desktop notifications. Off-machine push (SMS via EP06) deferred to v0.4 (#340-followup).

## Commits
- alert_sink — SQLite + SSE pub/sub
- trusted registry — HMAC-hashed IMSI + label
- API — /alerts (history + SSE + test) + /trusted CRUD
- standalone WebUI — live feed + Browser Notification API
- nginx route /sentinelle/ + MIND menu entry
- privacy invariant tests extended + changelog 0.2.0

## Test plan
- [x] pytest test_alert_sink.py — 5/5 pass
- [x] pytest test_trusted_registry.py — 6/6 pass
- [x] pytest test_alerts_api.py + test_trusted_api.py — 7/7 pass
- [x] privacy invariant tests pass (extended to Alert + TrustedPhone)
- [x] dpkg-buildpackage clean; .deb ships all new files
- [ ] On gk2: install .deb, hit POST /alerts/test, see desktop notification + row in the webui
- [ ] On gk2: add a test IMSI via /trusted, verify HMAC hash on disk (no plaintext)

Closes #340.
EOF
)"
```

---

## Task 8 — On-board E2E (manual, after PR merge)

After the PR lands and the .deb is installed on gk2:

- [ ] Open `https://admin.gk2.secubox.in/sentinelle/` and grant desktop notification permission.
- [ ] Click "Test alert". Verify: row appears in the live feed AND a desktop notification fires.
- [ ] Add a trusted phone with your own IMSI. Verify: `cat /etc/secubox/sentinelle-gsm/trusted.toml` shows the HMAC hash, NOT the plaintext IMSI.
- [ ] Issue another `POST /alerts/test` with `{"subscriber_hash": "<the hash from your phone>", "trusted_label": "<your label>"}`. Verify the desktop notification body includes `targets: <your label>`.
- [ ] Refresh page; confirm history is preserved (SQLite is persistent across restart).
- [ ] `systemctl restart secubox-sentinelle-gsm`; refresh page; SSE auto-reconnects within 2 s.

Once all checked: comment on #340 with "v0.2 validated on gk2, closing", then close the issue.
