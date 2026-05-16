# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote lease Pydantic models."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


LeaseAction = Literal["add", "old", "del", "discover"]


class LeaseEvent(BaseModel):
    """Body of POST /api/v1/eye-remote/lease-events.

    Sent by /usr/lib/secubox/eye-remote-leasewatch.sh on every dnsmasq
    dhcp-script invocation.
    """

    action: LeaseAction
    mac: str = Field(pattern=r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    ip: str
    hostname: str | None = None


class LeaseRecord(BaseModel):
    """Element of GET /api/v1/eye-remote/leases response."""

    mac: str
    ip: str
    hostname: str | None
    serial: str | None
    last_seen: int | None
    approved: bool = True  # Phase 1: every reservation is auto-approved
