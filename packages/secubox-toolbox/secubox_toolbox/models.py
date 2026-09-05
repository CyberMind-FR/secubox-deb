# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox-Deb :: ToolBoX — pydantic schemas (Config + DTOs)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


# ───────────────── Config (TOML) ─────────────────

class APCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ssid: str = "VILLAGE3B"
    iface: str = "wlxa854b2428fbb"
    channel: int = 1
    band: Literal["2g", "5g"] = "2g"


class DHCPCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    range_start: str = "10.99.0.10"
    range_end: str = "10.99.0.250"
    lease_ttl: str = "1h"
    gateway: str = "10.99.0.1"
    dns: list[str] = ["10.99.0.1"]


class PortalCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    listen_host: str = "10.99.0.1"
    listen_port: int = 8088
    admin_path: str = "/toolbox/admin"
    mac_salt_ref: str = "file:///etc/secubox/secrets/toolbox-mac-salt"
    report_ttl: str = "24h"


class R2Cfg(BaseModel):
    """TLS-break R2 — uniquement sur opt-in explicite."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    mitm_listen: str = "10.99.0.1:8080"
    ca_bundle: str = "/etc/secubox/toolbox/ca/ca.pem"
    ca_key: str = "/etc/secubox/toolbox/ca/key.pem"


class AddonsCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cookies: str = "http+unix:///run/secubox/cookies.sock/inject"
    dpi: str = "http+unix:///run/secubox/dpi.sock/classify"
    avatar: str = "http+unix:///run/secubox/avatar.sock/fingerprint"
    ja4: str = "http+unix:///run/secubox/threat-analyst.sock/ja4"
    soc_relay: str = "http+unix:///run/secubox/soc.sock/event"


class QuarantineCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    score_throttle: int = 30
    score_quarantine: int = 70


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    ap: APCfg = APCfg()
    dhcp: DHCPCfg = DHCPCfg()
    portal: PortalCfg = PortalCfg()
    r2: R2Cfg = R2Cfg()
    addons: AddonsCfg = AddonsCfg()
    quarantine: QuarantineCfg = QuarantineCfg()


# ───────────────── DTOs ─────────────────

class StatusResp(BaseModel):
    ip: str | None = None
    mac_hash: str | None = None
    validated: bool = False
    r2_consented: bool = False
    score: int = 0


class AcceptResp(BaseModel):
    ok: bool
    mac_hash: str
    r2: bool
    expires_in: str = "24h"


class ClientRow(BaseModel):
    """Row dans la vue admin."""
    mac_hash: str
    ip: str
    state: Literal["validated", "throttle", "quarantine"]
    score: int = 0
    first_seen: int
    last_seen: int


class ConsentEvent(BaseModel):
    """Preuve R2 opt-in stockée pour traçabilité."""
    mac_hash: str
    ts: int
    ip: str
    user_agent: str | None = None
    ttl_seconds: int = 86400


class EventLog(BaseModel):
    """Generic event from mitmproxy addons or SOC."""
    mac_hash: str
    ts: int
    source: Literal["cookies", "dpi", "avatar", "ja4", "soc"]
    payload: dict


class ReportToken(BaseModel):
    token: str = Field(min_length=24)
    mac_hash: str
    expires_at: int
