# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-antirootkit :: api/main.py

FastAPI app exposing the exec forensic log, the alert queue and the
manual quarantine-prep button.

Root path: /api/v1/antirootkit
Socket:    /run/secubox/antirootkit.sock (Unix socket, no TCP — wired by the
           systemd unit shipped in Task 11)
DB:        /var/lib/secubox/antirootkit/execlog.db (override via
           ANTIROOTKIT_DB_PATH env) — append-only exec forensic log.
           /var/lib/secubox/antirootkit/alerts.db (override via
           ANTIROOTKIT_ALERTS_DB_PATH env) — capped alert queue, shared
           with the sbx-antirootkitd.service daemon process (SEPARATE
           from this API process) which is what appends to it.

Read endpoints (/status, /execlog, /alerts): public.
Mutating endpoint (/quarantine-prep): requires JWT via Depends(require_jwt).
POST /quarantine-prep NEVER executes anything — it only returns the PLAN
computed by api.quarantine.prepare() (a dict of shell command strings the
operator may choose to run separately).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from api.execlog import ExecLog
from api.alertstore import AlertStore
from api import quarantine

# ---------------------------------------------------------------------------
# Optional JWT dependency — gracefully degrade when secubox_core is not
# installed (dev / off-box smoke-test), same pattern as secubox-annuaire and
# secubox-proxypac.
# ---------------------------------------------------------------------------
try:
    from secubox_core.auth import require_jwt as _require_jwt  # type: ignore

    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

    async def _require_jwt():  # type: ignore[misc]
        """No-op JWT guard when secubox_core is not installed (dev / off-box)."""
        return None


def require_jwt():
    """Return the real or stub JWT dependency (overridable in tests)."""
    return Depends(_require_jwt)


# ---------------------------------------------------------------------------
# ExecLog singleton — see api/execlog.py: sqlite3 defaults to
# check_same_thread=True, but FastAPI sync `def` routes run in a threadpool
# worker thread, so the module-level ExecLog MUST be opened with
# check_same_thread=False (append-only single-writer log).
# ---------------------------------------------------------------------------
DEFAULT_DB_PATH = os.environ.get(
    "ANTIROOTKIT_DB_PATH", "/var/lib/secubox/antirootkit/execlog.db"
)
DEFAULT_ALERTS_DB_PATH = os.environ.get(
    "ANTIROOTKIT_ALERTS_DB_PATH", "/var/lib/secubox/antirootkit/alerts.db"
)


def _default_execlog() -> ExecLog:
    path = Path(DEFAULT_DB_PATH)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        # dev/off-box fallback: no write access to /var/lib/secubox
        path = Path(tempfile.gettempdir()) / "secubox-antirootkit-execlog.db"
    return ExecLog(str(path), check_same_thread=False)


def _default_alertstore() -> AlertStore:
    # Same db_path as the daemon's AlertStore (api/daemon.py ALERTS_DB_PATH)
    # — this is what makes GET /alerts see what a SEPARATE daemon process
    # appended (a plain in-memory list would not survive that boundary).
    path = Path(DEFAULT_ALERTS_DB_PATH)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        # dev/off-box fallback: no write access to /var/lib/secubox
        path = Path(tempfile.gettempdir()) / "secubox-antirootkit-alerts.db"
    return AlertStore(str(path))


class QuarantinePrepRequest(BaseModel):
    path: str
    c2_ip: Optional[str] = None
    unit: Optional[str] = None


def create_app(
    execlog: Optional[ExecLog] = None, alertstore: Optional[AlertStore] = None
) -> FastAPI:
    """Build the FastAPI app. Tests inject a temp-db ExecLog/AlertStore;
    production (module-level `app` below) uses the default singletons."""
    app = FastAPI(title="SecuBox Anti-Rootkit API", version="1.0.0")
    log = execlog if execlog is not None else _default_execlog()
    astore = alertstore if alertstore is not None else _default_alertstore()

    @app.get("/status")
    def get_status():
        """Small status blob for the panel header/sidebar badge.

        Uses log.count() (the true table size), not len(recent()) — the
        latter is capped at its `limit` and would freeze the badge at 100
        once the log grows past that on a live host.
        """
        return {"execlog_rows": log.count()}

    @app.get("/execlog")
    def get_execlog(limit: int = 100):
        """Recent exec forensic log rows (most recent first)."""
        return log.recent(limit=limit)

    @app.get("/alerts")
    def get_alerts(limit: int = 100):
        """Current alert queue (most recent first).

        Backed by api.alertstore.AlertStore, a SQLite db shared with the
        exec-watch daemon process (api/daemon.py, a SEPARATE systemd unit)
        which appends an alert here whenever it jails an unknown/non-dpkg-
        backed process (api.alerts.build_alert) — this is what makes the
        endpoint reflect real anti-escape events rather than a hardcoded
        empty stub or a daemon-process-local list.
        """
        return astore.recent(limit=limit)

    @app.post("/quarantine-prep", dependencies=[require_jwt()])
    def post_quarantine_prep(req: QuarantinePrepRequest):
        """Return the quarantine PLAN for a confirmed-malicious binary.

        Delegates entirely to api.quarantine.prepare(), which is
        side-effect-free: this route NEVER executes chmod/cp/nft/systemctl,
        it only returns the plan as data for the operator to review and run
        manually (the manual quarantine button's backend).
        """
        return quarantine.prepare(req.path, c2_ip=req.c2_ip, unit=req.unit)

    return app


app = create_app()
