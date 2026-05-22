# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-sentinelle-gsm :: host FastAPI control plane.

Host-resident (NO LXC — the SDR is host USB hardware). Unix socket
/run/secubox/sentinelle-gsm.sock, reverse-proxied at /api/v1/sensor/gsm/
on the canonical hub vhost.

v0.1.0 surface (scaffold):
  GET  /status            — components + privacy invariant flag + mode
  GET  /components        — sdr / livemon / analyzer / host-api states
  GET  /access            — exposed endpoints
  GET  /cells             — observed cells (empty until v0.2 wires gr-gsm)
  GET  /alerts            — active/historized alerts (empty in v0.1)
  POST /mode              — flip PROD ↔ LAB (LAB requires consent ack + audit)
  GET  /healthz

OPAD/privacy invariant proof: /status returns
`captures_plaintext_imsi: false` and `mode: prod`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

sys.path.insert(0, "/usr/lib/secubox/sentinelle-gsm/lib")

from sentinelle_gsm import CAPTURES_PLAINTEXT_IMSI, Mode  # noqa: E402
from sentinelle_gsm.alert_sink import Alert, AlertSink   # noqa: E402
from sentinelle_gsm.baseline import CellBaseline         # noqa: E402
from sentinelle_gsm.gsmtap_listener import GsmtapListener  # noqa: E402
from sentinelle_gsm.l3_decode import (                   # noqa: E402
    L3Decode, MID_TYPE_IMSI, MID_TYPE_TMSI,
)
from sentinelle_gsm.livemon_runner import LivemonRunner, detect_rtlsdr_usb  # noqa: E402
from sentinelle_gsm.observations import (                # noqa: E402
    ObservationsDB, PagingEvent, Sighting,
)
from sentinelle_gsm.observer import Anonymizer           # noqa: E402
from sentinelle_gsm.scoring_engine import ScoringEngine  # noqa: E402
from sentinelle_gsm.trusted import TrustedRegistry       # noqa: E402

_log = logging.getLogger("secubox.sentinelle-gsm.api")

SECRETS_DIR = Path(os.environ.get("SECUBOX_SECRETS_DIR", "/etc/secubox/secrets"))
HMAC_KEY_FILE = SECRETS_DIR / "sentinelle-gsm-hmac"
MODE_FILE = Path("/var/lib/secubox/sentinelle-gsm/mode")  # PROD by default

app = FastAPI(
    title="SecuBox SENTINELLE-GSM",
    description="Passive GSM rogue-BTS sensor (MIND layer) — RX only, off-path",
    version="0.2.0",
)


# ── v0.2: alert sink + trusted registry singletons ──────────────────────────
#
# Auth note: this package is reverse-proxied through nginx + Authelia (see
# nginx/sentinelle-gsm.conf), which terminates JWT before forwarding to the
# Unix socket. `require_jwt` is therefore a no-op dependency here; it exists
# as a hook so tests (and future host-direct callers) can override it via
# `app.dependency_overrides[require_jwt]`.

def require_jwt() -> dict:
    """No-op auth hook. Real JWT enforcement happens at nginx/Authelia."""
    return {"sub": "nginx-authelia"}


_alert_sink: Optional[AlertSink] = None
_trusted_registry: Optional[TrustedRegistry] = None

ALERTS_DB_PATH = Path("/var/lib/secubox/sentinelle-gsm/alerts.db")
TRUSTED_REGISTRY_PATH = Path("/etc/secubox/sentinelle-gsm/trusted.json")


def _get_anonymizer() -> Anonymizer:
    """Load the HMAC key from disk; fall back to an ephemeral key.

    The ephemeral fallback exists so the API can boot on a freshly-installed
    box where postinst hasn't yet generated the key. In that case the
    trusted-registry hashes are stable for the lifetime of the process but
    lost on restart — the operator should re-add trusted phones once the
    persistent HMAC key is in place.
    """
    mode = _read_mode()
    if _hmac_key_present():
        return Anonymizer.from_file(HMAC_KEY_FILE, mode=mode)
    return Anonymizer.ephemeral(mode=mode)


def get_alert_sink() -> AlertSink:
    if _alert_sink is None:
        raise RuntimeError("alert_sink not initialised")
    return _alert_sink


def get_trusted_registry() -> TrustedRegistry:
    if _trusted_registry is None:
        raise RuntimeError("trusted_registry not initialised")
    return _trusted_registry


@app.on_event("startup")
def _init_v0_2_singletons() -> None:
    global _alert_sink, _trusted_registry
    if _alert_sink is None:
        _alert_sink = AlertSink(ALERTS_DB_PATH)
    if _trusted_registry is None:
        _trusted_registry = TrustedRegistry(TRUSTED_REGISTRY_PATH, _get_anonymizer())


# ── v0.3: scan control (livemon runner + GSMTAP listener + observations DB) ──
#
# The CHILD grgsm_livemon_headless claims the RTL-SDR; the parent never does.
# This lets ad-hoc tools (rtl_test, kalibrate) coexist with the service when
# no scan is active (closes #344).

_livemon: Optional[LivemonRunner] = None
_listener: Optional[GsmtapListener] = None
_obs_db: Optional[ObservationsDB] = None
_consume_task: Optional[asyncio.Task] = None

OBSERVATIONS_DB_PATH = Path("/var/lib/secubox/sentinelle-gsm/observations.db")


def get_livemon() -> LivemonRunner:
    if _livemon is None:
        raise RuntimeError("livemon runner not initialised")
    return _livemon


def get_listener() -> GsmtapListener:
    if _listener is None:
        raise RuntimeError("gsmtap listener not initialised")
    return _listener


def get_obs_db() -> ObservationsDB:
    if _obs_db is None:
        raise RuntimeError("observations db not initialised")
    return _obs_db


@app.on_event("startup")
def _init_v0_3_singletons() -> None:
    global _livemon, _listener, _obs_db
    global _l3, _scoring, _baseline
    if _livemon is None:
        _livemon = LivemonRunner()
    if _listener is None:
        _listener = GsmtapListener()
    if _obs_db is None:
        _obs_db = ObservationsDB(OBSERVATIONS_DB_PATH)
    # v0.3.1: L3 decoder + baseline + scoring engine
    if _baseline is None:
        _baseline = CellBaseline(_obs_db._db)
    if _l3 is None:
        _l3 = L3Decode(_get_anonymizer())
    if _scoring is None:
        _scoring = ScoringEngine(_baseline)


# ── v0.3.1: L3 decode + scoring + baseline singletons ───────────────────
#
# The consume loop pipes Observation.raw_l3 through L3Decode → updates
# the operator baseline → runs the 8-heuristic ScoringEngine → matches
# paged subscriber hashes against the trusted registry → emits an
# Alert via AlertSink when score >= ALERT_THRESHOLD.

_l3:       Optional[L3Decode] = None
_scoring:  Optional[ScoringEngine] = None
_baseline: Optional[CellBaseline] = None

ALERT_THRESHOLD = int(os.environ.get("SENTINELLE_ALERT_THRESHOLD", "60"))


def get_l3() -> L3Decode:
    if _l3 is None:
        raise RuntimeError("l3 decoder not initialised")
    return _l3


def get_scoring() -> ScoringEngine:
    if _scoring is None:
        raise RuntimeError("scoring engine not initialised")
    return _scoring


def get_baseline() -> CellBaseline:
    if _baseline is None:
        raise RuntimeError("baseline not initialised")
    return _baseline


# Map paging request L3 message type → human label for paging_events.
_PAGING_REQUEST_LABEL = {
    0x21: "paging-1",
    0x22: "paging-2",
    0x24: "paging-3",
}


def _cell_id_from_parsed(parsed_cell_info, obs) -> str:
    """Build a cell_id from L3-parsed cell_info if complete, else fall back
    to the arfcn/channel composite key. Always returns a non-empty string."""
    ci = parsed_cell_info
    if (ci is not None and ci.mcc is not None and ci.mnc is not None
            and ci.lac is not None and ci.ci is not None):
        return f"{ci.mcc}-{ci.mnc}-{ci.lac}-{ci.ci}"
    return obs.cell_id or f"arfcn-{obs.arfcn}-ch-{obs.channel}"


async def _process_observation(obs) -> None:
    """Handle ONE GSMTAP Observation: L3-decode, persist, score, alert.

    Extracted from _consume_observations() for testability. Tests can
    feed synthesized Observation instances directly without driving the
    UDP listener / consume coroutine.

    Step-by-step (per v0.3.1 plan §6.3):
      1. L3-decode obs.raw_l3 → ParsedFrame(cell_info?, paging?)
      2. Derive cell_id from parsed cell_info OR fallback arfcn-ch key
      3. upsert_sighting() with whatever metadata we have
      4. record_paging() for every paged subscriber (already hashed)
      5. baseline.consider() so the cell graduates after N sightings
      6. scoring.evaluate() → CellScore
      7. score >= threshold → match each paged hash against trusted
         registry; emit a labeled-or-anomaly-only Alert.
    """
    l3 = get_l3()
    db = get_obs_db()
    baseline = get_baseline()
    scoring = get_scoring()
    sink = get_alert_sink()
    trusted = get_trusted_registry()

    parsed = l3.parse(obs.raw_l3 or b"")
    cell_info = parsed.cell_info
    paging = parsed.paging

    cell_id = _cell_id_from_parsed(cell_info, obs)

    # Prefer parsed (BCCH-derived) metadata over header-only fields.
    mcc = (cell_info.mcc if cell_info and cell_info.mcc is not None
           else obs.mcc)
    mnc = (cell_info.mnc if cell_info and cell_info.mnc is not None
           else obs.mnc)
    lac = (cell_info.lac if cell_info and cell_info.lac is not None
           else obs.lac)
    ci_val = (cell_info.ci if cell_info and cell_info.ci is not None
              else obs.ci)
    cipher_a5 = cell_info.a5_advertised if cell_info else None

    try:
        db.upsert_sighting(Sighting(
            cell_id=cell_id, arfcn=obs.arfcn,
            mcc=mcc, mnc=mnc, lac=lac, ci=ci_val,
        ))
    except ValueError as exc:
        _log.warning("observations: refused write: %s", exc)
        return

    if paging is not None:
        label = _PAGING_REQUEST_LABEL.get(paging.paging_type, "paging")
        for pid in paging.identities:
            try:
                db.record_paging(PagingEvent(
                    ts=obs.ts, cell_id=cell_id,
                    subscriber_hash=pid.subscriber_hash,
                    request_type=label,
                ))
            except ValueError as exc:
                _log.warning("paging_events: refused write: %s", exc)

    baseline.consider(
        cell_id, mcc=mcc, mnc=mnc, lac=lac,
        arfcn=obs.arfcn, cipher_a5=cipher_a5,
    )

    result = scoring.evaluate(cell_info, paging, obs.arfcn)
    if result.score < ALERT_THRESHOLD:
        return

    reason = "; ".join(result.reasons) if result.reasons else "anomaly"

    # Try to match each paged subscriber against trusted registry.
    matched: list[tuple[str, str]] = []   # (hash, label)
    if paging is not None:
        for pid in paging.identities:
            tp = trusted.lookup_by_hash(pid.subscriber_hash)
            if tp is not None:
                matched.append((pid.subscriber_hash, tp.label))

    if matched:
        # One alert per matched trusted phone — operator wants per-device
        # labeled visibility.
        for sub_hash, label in matched:
            try:
                sink.write(Alert(
                    cell_id=cell_id, arfcn=obs.arfcn,
                    score=result.score, reason=reason,
                    subscriber_hash=sub_hash, trusted_label=label,
                ))
            except ValueError as exc:
                _log.warning("alert: refused write: %s", exc)
    else:
        # Anomaly-only — score crossed threshold but no trusted match.
        try:
            sink.write(Alert(
                cell_id=cell_id, arfcn=obs.arfcn,
                score=result.score, reason=reason,
                subscriber_hash=None, trusted_label=None,
            ))
        except ValueError as exc:
            _log.warning("alert: refused write: %s", exc)


async def _consume_observations() -> None:
    """Drain the GSMTAP listener and process each observation.

    Cancellation-safe: /scan/stop cancels this task first, then stops
    the listener + runner. Per-observation errors are logged and the
    loop continues — a single malformed frame must NOT kill the scan.
    """
    listener = get_listener()
    try:
        async for obs in listener.observations():
            try:
                await _process_observation(obs)
            except Exception:           # noqa: BLE001
                _log.exception("process_observation failed; continuing")
    except asyncio.CancelledError:
        # Normal path on /scan/stop — propagate so the task transitions
        # to CANCELLED rather than swallowing.
        raise
    except Exception:           # noqa: BLE001
        _log.exception("consume loop crashed")
        raise


def _read_mode() -> Mode:
    """Read the current PROD/LAB mode marker (PROD if file absent)."""
    try:
        raw = MODE_FILE.read_text().strip().lower()
        return Mode(raw)
    except (FileNotFoundError, PermissionError, ValueError):
        return Mode.PROD


def _hmac_key_present() -> bool:
    try:
        return HMAC_KEY_FILE.exists() and HMAC_KEY_FILE.stat().st_size >= 32
    except (PermissionError, OSError):
        return False


def _sdr_present() -> bool:
    return detect_rtlsdr_usb() is not None


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/status")
def status() -> dict:
    components = _components_list()
    states = {c["name"]: c["state"] for c in components}
    if states.get("sdr") == "present" and states.get("livemon") == "running" \
       and states.get("analyzer") == "running":
        overall = "green"
    elif states.get("host-api") == "running":
        overall = "yellow"  # API up but no SDR — expected scaffold state
    else:
        overall = "red"
    mode = _read_mode()
    return {
        "module": "sentinelle-gsm",
        "version": "0.1.0",
        "overall": overall,
        "states": states,
        "mode": mode.value,
        # OPAD / privacy invariant flag — auditor-visible.
        "captures_plaintext_imsi": (mode is Mode.LAB),  # only LAB can capture
        "captures_plaintext_imsi_in_prod": CAPTURES_PLAINTEXT_IMSI,  # always False
        "rx_only": True,  # NEVER emits RF; structural property
    }


def _components_list() -> list[dict]:
    sdr_st = "present" if _sdr_present() else "absent"
    # v0.1 doesn't actually run livemon/analyzer worker threads.
    livemon_st = "running" if _sdr_present() else "idle"
    analyzer_st = "running" if _sdr_present() else "idle"
    key_st = "ok" if _hmac_key_present() else "missing"
    return [
        {"name": "sdr", "state": sdr_st,
         "detail": "RTL-SDR USB (0bda:2832/2838, 1d50:604b, 1f4d:0001)"},
        {"name": "livemon", "state": livemon_st,
         "detail": "grgsm_livemon_headless → GSMTAP udp://127.0.0.1:4729"},
        {"name": "analyzer", "state": analyzer_st,
         "detail": "GSMTAP parser + scoring (8 heuristics)"},
        {"name": "hmac-key", "state": key_st,
         "detail": str(HMAC_KEY_FILE)},
        {"name": "host-api", "state": "running",
         "detail": "secubox-sentinelle-gsm.service (uvicorn)"},
    ]


@app.get("/components")
def components() -> dict:
    return {"module": "sentinelle-gsm", "version": "0.1.0",
            "components": _components_list()}


@app.get("/access")
def access() -> dict:
    return {
        "module": "sentinelle-gsm",
        "access": [
            {"endpoint": "/run/secubox/sentinelle-gsm.sock",
             "scope": "host-only", "auth": "Unix socket (root + secubox)"},
            {"endpoint": "/api/v1/sensor/gsm/ (via canonical hub vhost)",
             "scope": "lan", "auth": "JWT (Authelia / secubox-zkp-auth)"},
        ],
    }


@app.get("/cells")
def cells() -> dict:
    """Observed cells + scores. Empty in v0.1.0 (scoring engine stubbed)."""
    if not _sdr_present():
        raise HTTPException(503, "sdr-absent")
    return {"cells": []}  # v0.2 wires the GSMTAP feed


class TrustedAddBody(BaseModel):
    imsi: str
    label: str


@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(limit: int = 100, since: float = 0.0) -> dict:
    """Paginated alert history from the SQLite-backed sink."""
    return {
        "alerts": [
            asdict(a) for a in get_alert_sink().list(limit=limit, since=since)
        ]
    }


@app.get("/alerts/stream", dependencies=[Depends(require_jwt)])
async def stream_alerts() -> StreamingResponse:
    """Server-Sent Events live feed of anomaly alerts.

    Headers disable buffering at every layer (nginx via X-Accel-Buffering,
    HTTP client caches via Cache-Control). The async generator runs until
    the client disconnects; FastAPI handles cancellation.
    """
    sink = get_alert_sink()
    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(
        sink.stream(), media_type="text/event-stream", headers=headers
    )


@app.post("/alerts/test", dependencies=[Depends(require_jwt)])
async def test_alert(body: Optional[dict] = Body(default=None)) -> dict:
    """Manual operator trigger — writes a synthetic alert end-to-end.

    A privacy-guard violation (plaintext-IMSI shape detected in any field)
    surfaces as a 500 so the upstream UI / curl gets a clean error rather
    than a stack trace. The error message is preserved.
    """
    body = body or {}
    a = Alert(
        cell_id=body.get("cell_id", "208-01-100-99999"),
        arfcn=body.get("arfcn", 124),
        score=body.get("score", 80),
        reason=body.get("reason", "operator-test"),
        subscriber_hash=body.get("subscriber_hash"),
        trusted_label=body.get("trusted_label"),
    )
    try:
        written = get_alert_sink().write(a)
    except ValueError as e:
        raise HTTPException(500, str(e))
    return {"ok": True, "id": written.id}


@app.get("/trusted", dependencies=[Depends(require_jwt)])
async def list_trusted() -> dict:
    return {"phones": [asdict(p) for p in get_trusted_registry().list()]}


@app.post("/trusted", dependencies=[Depends(require_jwt)])
async def add_trusted(body: TrustedAddBody) -> dict:
    try:
        p = get_trusted_registry().add(body.imsi, body.label)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return asdict(p)


@app.delete("/trusted/{phone_id}", dependencies=[Depends(require_jwt)])
async def delete_trusted(phone_id: str) -> dict:
    if not get_trusted_registry().delete(phone_id):
        raise HTTPException(404, "not found")
    return {"ok": True}


# ── JOURNAL STREAMING (v0.2.2) ─────────────────────────────────────────
# Read-only SSE feed of `journalctl -u secubox-sentinelle-gsm -f -o json`.
# The service user is in the systemd-journal group via postinst so no
# elevated privileges are needed at runtime. The async generator runs
# `journalctl` as a child process and yields each JSON line as an SSE
# `event: log` chunk.

async def _journal_stream() -> "AsyncIterator[str]":  # noqa: F821
    import asyncio
    import json as _json
    import shutil

    journalctl = shutil.which("journalctl") or "/usr/bin/journalctl"
    proc = await asyncio.create_subprocess_exec(
        journalctl,
        "-u", "secubox-sentinelle-gsm",
        "-f",                # follow
        "-n", "50",          # bootstrap with the last 50 lines
        "-o", "json",
        "--no-pager",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    # Emit a `: subscribed` SSE comment IMMEDIATELY so browsers transition
    # EventSource from CONNECTING to OPEN even if the journal happens to
    # be idle. Then loop with a 30 s heartbeat that pings the connection
    # alive across HAProxy/mitmproxy/nginx idle timeouts.
    yield ": subscribed\n\n"
    HEARTBEAT_SEC = 30.0
    try:
        assert proc.stdout is not None
        while True:
            try:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=HEARTBEAT_SEC
                )
            except asyncio.TimeoutError:
                yield ": ping\n\n"
                continue
            if not line:
                break
            try:
                entry = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            # Keep only the fields the UI actually needs — message + ts.
            payload = {
                "ts": float(entry.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000,
                "priority": int(entry.get("PRIORITY", 6)),
                "message": entry.get("MESSAGE", ""),
                "syslog_id": entry.get("SYSLOG_IDENTIFIER", ""),
            }
            yield "event: log\ndata: " + _json.dumps(payload) + "\n\n"
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()


@app.get("/journal/stream", dependencies=[Depends(require_jwt)])
async def stream_journal() -> StreamingResponse:
    """Server-Sent Events live feed of this service's systemd journal.

    Reads `journalctl -u secubox-sentinelle-gsm -f -o json` and forwards
    each entry as an SSE `event: log` chunk with the message + priority
    + RFC3339 timestamp. Uses the existing systemd-journal group
    membership (set in postinst).
    """
    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(
        _journal_stream(), media_type="text/event-stream", headers=headers
    )


@app.post("/mode")
def set_mode(payload: dict = Body(...)) -> dict:
    """Flip between PROD ↔ LAB.

    LAB requires an explicit `consent_ack: true` field — without it, the
    request is refused. Every successful transition writes to
    /var/log/secubox/sentinelle-gsm-audit.log (audit trail).
    """
    target = (payload.get("mode") or "").lower()
    if target not in ("prod", "lab"):
        raise HTTPException(400, "mode must be 'prod' or 'lab'")
    target_mode = Mode(target)
    if target_mode is Mode.LAB and not payload.get("consent_ack"):
        raise HTTPException(
            400,
            "LAB mode requires consent_ack=true (owned-SIM / consented-device statement)"
        )
    try:
        MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
        MODE_FILE.write_text(target_mode.value + "\n")
    except (PermissionError, OSError) as e:
        raise HTTPException(500, f"could not persist mode: {e}")
    # Audit log
    try:
        audit_log = Path("/var/log/secubox/sentinelle-gsm-audit.log")
        audit_log.parent.mkdir(parents=True, exist_ok=True)
        import time
        with open(audit_log, "a") as f:
            f.write(f"{time.time():.3f} mode-flip → {target_mode.value} "
                    f"(consent_ack={bool(payload.get('consent_ack'))})\n")
    except (PermissionError, OSError):
        pass  # don't 500 on audit-log fail; mode flip already persisted
    return {"ok": True, "mode": target_mode.value}


# ── SCAN CONTROL (v0.3.0) ───────────────────────────────────────────────
# Lifecycle: POST /scan/start spawns grgsm_livemon_headless, binds the
# UDP listener and starts the consume loop that drains Observations
# into ObservationsDB. POST /scan/stop cancels the consume task FIRST,
# then stops the runner + listener — so no orphan subprocess remains.

class ScanStartBody(BaseModel):
    freq: str
    # v0.3.2: optional tuning. Each falls back to grgsm_livemon_headless's
    # own default when None. Mostly useful when the carrier RF environment
    # needs more gain or the dongle's crystal needs a ppm correction.
    gain: Optional[float] = None
    samp_rate: Optional[str] = None
    ppm: Optional[float] = None
    # gr-osmosdr device-args. Default rtl=0 forces the RTL-SDR backend
    # (osmosdr's default loads UHD/USRP and fails when none is plugged).
    # Operators can override to experiment with alternative syntaxes
    # while we figure out why livemon rejects what scanner accepts.
    args: str = "rtl=0"


def _scan_status_payload(st) -> dict:
    """Render a LivemonRunner.ScanStatus dataclass as JSON-safe dict.

    The test fixture replaces _livemon with a MagicMock whose status()
    returns a MagicMock-shaped object (not a real dataclass) — pluck
    attributes individually so both paths work.
    """
    return {
        "running": bool(getattr(st, "running", False)),
        "pid": getattr(st, "pid", None),
        "freq": getattr(st, "freq", None),
        "started_at": getattr(st, "started_at", None),
        "stderr_tail": getattr(st, "stderr_tail", "") or "",
    }


@app.post("/scan/start", dependencies=[Depends(require_jwt)])
async def scan_start(body: ScanStartBody) -> dict:
    """Spawn grgsm_livemon_headless on `freq`, start listener + consume loop."""
    global _consume_task
    if _consume_task is not None and not _consume_task.done():
        raise HTTPException(409, "scan already running")
    listener = get_listener()
    runner = get_livemon()
    try:
        await listener.start()
    except OSError as e:
        raise HTTPException(500, f"listener bind failed: {e}")
    try:
        status = await runner.start(
            body.freq,
            gain=body.gain,
            samp_rate=body.samp_rate,
            ppm=body.ppm,
            args=body.args,
        )
    except RuntimeError as e:
        # runner refused (already running) — undo the listener bind
        await listener.stop()
        raise HTTPException(409, str(e))
    except FileNotFoundError as e:
        await listener.stop()
        raise HTTPException(500, f"grgsm_livemon_headless missing: {e}")
    _consume_task = asyncio.create_task(_consume_observations())
    return _scan_status_payload(status)


@app.post("/scan/stop", dependencies=[Depends(require_jwt)])
async def scan_stop() -> dict:
    """Cancel consume task, then stop runner + listener (in that order)."""
    global _consume_task
    if _consume_task is not None:
        _consume_task.cancel()
        try:
            await _consume_task
        except asyncio.CancelledError:
            pass
        except Exception:           # noqa: BLE001
            _log.exception("consume task exited with error during stop")
        _consume_task = None
    runner = get_livemon()
    listener = get_listener()
    status = await runner.stop()
    await listener.stop()
    return _scan_status_payload(status)


@app.get("/scan/status", dependencies=[Depends(require_jwt)])
async def scan_status() -> dict:
    """Current runner state (running / pid / freq / stderr-tail)."""
    return _scan_status_payload(get_livemon().status())


@app.get("/observations", dependencies=[Depends(require_jwt)])
async def list_observations(limit: int = 200) -> dict:
    """Recent cell sightings, newest first. `limit` is capped at 1000."""
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000
    return {
        "sightings": [asdict(s) for s in get_obs_db().sightings(limit=limit)],
    }


# ── v0.3.1: baseline + scoring endpoints ────────────────────────────────
#
# /baseline           — read graduated cells
# /baseline/learn     — enable learn-mode for a sweep window
# /scoring/thresholds — read / write the 8-heuristic threshold table
#
# JWT enforcement is delegated to nginx + Authelia upstream (require_jwt
# is a no-op hook here, overridable in tests).

class BaselineLearnBody(BaseModel):
    sweep_seconds: int = 300


@app.get("/baseline", dependencies=[Depends(require_jwt)])
def list_baseline(limit: int = 200) -> dict:
    """Operator baseline — list of cells graduated to baseline."""
    limit = max(1, min(1000, limit))
    return {"cells": [asdict(c) for c in get_baseline().list(limit=limit)]}


@app.post("/baseline/learn", dependencies=[Depends(require_jwt)])
def baseline_learn(body: BaselineLearnBody) -> dict:
    """Flip the baseline into learn-mode for `sweep_seconds`.

    Cells observed during that window graduate to baseline immediately
    (initial learn_count = LEARN_THRESHOLD) instead of waiting for the
    default N=3 sightings. The operator must start a scan separately.
    """
    bl = get_baseline()
    bl.set_learn_mode(body.sweep_seconds)
    _log.info("baseline learn mode enabled for %ds", body.sweep_seconds)
    import time
    return {"learn_mode_until": time.time() + body.sweep_seconds}


@app.get("/scoring/thresholds", dependencies=[Depends(require_jwt)])
def scoring_thresholds_get() -> dict:
    return {"thresholds": get_scoring().thresholds()}


@app.post("/scoring/thresholds", dependencies=[Depends(require_jwt)])
def scoring_thresholds_set(body: dict = Body(...)) -> dict:
    """Per-heuristic deep-merge of `body` into the live threshold table.

    Emits an audit log entry (caught by /journal/stream) listing which
    heuristics were touched — operators need a paper trail when scoring
    is tuned mid-deployment.
    """
    new = get_scoring().update_thresholds(body)
    _log.info("scoring thresholds updated: %s", list(body.keys()))   # audit
    return {"thresholds": new}


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "module": "sentinelle-gsm", "version": "0.1.0",
            "captures_plaintext_imsi_in_prod": CAPTURES_PLAINTEXT_IMSI,
            "rx_only": True}
