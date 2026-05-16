# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote leases router.

GET  /api/v1/eye-remote/leases         — list known gadgets
POST /api/v1/eye-remote/lease-events   — dhcp-script hook notifications
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter

from ..lib.leasefile import parse_leases
from ..lib.reservations import filter_active, parse_reservations
from ..models.lease import LeaseEvent, LeaseRecord

router = APIRouter(prefix="/eye-remote", tags=["eye-remote"])

_DEFAULT_LEASE_FILE = "/var/lib/misc/dnsmasq-eye-remote.leases"
_DEFAULT_RESERVATIONS_FILE = "/etc/secubox/eye-remote/reservations.conf"

log = logging.getLogger(__name__)


def _read(path_env: str, default: str) -> str:
    path = Path(os.environ.get(path_env, default))
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


@router.get("/leases", response_model=list[LeaseRecord])
def list_leases() -> list[LeaseRecord]:
    leases = parse_leases(_read("SECUBOX_EYE_LEASE_FILE", _DEFAULT_LEASE_FILE))
    reservations = parse_reservations(
        _read("SECUBOX_EYE_RESERVATIONS_FILE", _DEFAULT_RESERVATIONS_FILE)
    )
    active_macs = {l.mac.lower() for l in leases}
    by_mac = {r.mac.lower(): r for r in filter_active(reservations, active_macs)}

    now = int(time.time())
    out: list[LeaseRecord] = []
    for lease in leases:
        if lease.expiry < now:
            continue
        r = by_mac.get(lease.mac.lower())
        # Phase 1: last_seen is the lease expiry (we have no separate last-seen
        # store yet). When the lease-event POST notifier evolves into a small
        # registry in Phase 2, this will become the actual observation epoch.
        out.append(
            LeaseRecord(
                mac=lease.mac,
                ip=lease.ip,
                hostname=((r.hostname or lease.hostname) if r else lease.hostname),
                serial=None,
                last_seen=lease.expiry,
                approved=True,
            )
        )
    return out


@router.post("/lease-events")
def lease_event(body: LeaseEvent) -> dict[str, str]:
    log.info(
        "lease-event action=%s mac=%s ip=%s host=%s",
        body.action,
        body.mac,
        body.ip,
        body.hostname,
    )
    return {"status": "recorded"}
