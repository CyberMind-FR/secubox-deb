# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — Pydantic v2 data contracts
CyberMind — https://cybermind.fr

All models use the Pydantic v2 API (``model_config`` / ``field_validator``) —
the legacy v1 ``class Config`` / ``@validator`` decorators are not used
anywhere in this module.
"""
from __future__ import annotations

import re
import time
import uuid as _uuid
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def _now() -> float:
    return time.time()


# --- AUTH / ROOT: server (egress point) records ---------------------------


class ServerCreate(BaseModel):
    """Payload to provision a new VLESS+Reality+Vision egress point."""

    model_config = ConfigDict(extra="forbid")

    remark: str = Field(..., min_length=1, max_length=128)
    dest: str = Field(..., description="Reality camouflage target, host[:port] (SNI origin)")
    sni: str = Field(..., description="Server Name Indication presented to clients")
    listen_port: int = Field(443, ge=1, le=65535)
    dest_port: int = Field(443, ge=1, le=65535)
    flow: Literal["xtls-rprx-vision", ""] = "xtls-rprx-vision"
    short_id_count: int = Field(1, ge=1, le=8)

    @field_validator("dest", "sni")
    @classmethod
    def _no_scheme(cls, v: str) -> str:
        v = v.strip()
        if "://" in v:
            raise ValueError("dest/sni must be a bare host, not a URL")
        return v


class Server(BaseModel):
    """A provisioned Reality egress point, as persisted in ROOT storage."""

    model_config = ConfigDict(extra="forbid")

    id: str
    remark: str
    private_key: str
    public_key: str
    uuid: str
    dest: str
    sni: str
    listen_port: int
    dest_port: int
    flow: str = "xtls-rprx-vision"
    short_ids: List[str] = Field(default_factory=list)
    status: Literal["new", "applied", "running", "stopped", "disabled_volume_guard"] = "new"
    created_at: float = Field(default_factory=_now)
    updated_at: float = Field(default_factory=_now)

    @field_validator("short_ids")
    @classmethod
    def _validate_short_ids(cls, v: List[str]) -> List[str]:
        for sid in v:
            if len(sid) % 2 != 0 or not _HEX_RE.match(sid):
                raise ValueError(f"invalid shortId {sid!r}: must be even-length hex")
        return v


# --- Clients ----------------------------------------------------------------


class ClientCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    email: str = Field(..., min_length=1, max_length=128)
    flow: Literal["xtls-rprx-vision", ""] = "xtls-rprx-vision"


class Client(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    server_id: str
    uuid: str = Field(default_factory=lambda: str(_uuid.uuid4()))
    email: str
    short_id: str
    flow: str = "xtls-rprx-vision"
    created_at: float = Field(default_factory=_now)


# --- MIND: volume-guard configuration ---------------------------------------


class GuardConfig(BaseModel):
    """Sliding-window volume-guard policy (soft warn / hard disable)."""

    model_config = ConfigDict(extra="forbid")

    window_hours: int = Field(48, ge=1, le=24 * 30)
    soft_gb: float = Field(80.0, gt=0)
    hard_gb: float = Field(100.0, gt=0)
    action: Literal["disable"] = "disable"

    @field_validator("hard_gb")
    @classmethod
    def _hard_ge_soft(cls, v: float, info) -> float:
        soft = info.data.get("soft_gb")
        if soft is not None and v < soft:
            raise ValueError("hard_gb must be >= soft_gb")
        return v


class StatsPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    ts: float = Field(default_factory=_now)
    uplink: int = Field(0, ge=0)
    downlink: int = Field(0, ge=0)


# --- Validation / apply requests --------------------------------------------


class ValidateTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(..., min_length=1)
    port: int = Field(443, ge=1, le=65535)


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
