# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — schemas pydantic (Config + DTO).
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, ConfigDict


class RadioCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phy: str = "phy0"
    driver: Literal["ath9k", "ath9k_htc", "mt7615e", "mt76x2u", "ath10k_pci"] = "ath9k_htc"
    iface: str = "wlan0"


class RegCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    country: str = Field("FR", pattern=r"^[A-Z]{2}$")
    dfs: bool = True


class MeshCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    mesh_id: str = "gondwana-air"
    band: Literal["2g", "5g"] = "2g"
    freq: int = 2412
    sae_password_ref: str = "file:///etc/secubox/secrets/mesh-sae"


class APCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    ssid: str = "Gondwana-Air"
    band: Literal["2g", "5g"] = "2g"
    hs20: bool = False
    anqp: bool = False


class BackhaulCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["dbdc", "wired", "shared"] = "wired"


class OPADCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reactive: bool = False  # passif par défaut — NE PAS mettre true par défaut


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    radio: RadioCfg = RadioCfg()
    reg: RegCfg = RegCfg()
    mesh: MeshCfg = MeshCfg()
    ap: APCfg = APCfg()
    backhaul: BackhaulCfg = BackhaulCfg()
    opad: OPADCfg = OPADCfg()


# ----- DTO -----

class Peer(BaseModel):
    mac: str
    inactive_ms: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    signal_dbm: int | None = None
    tx_bitrate_mbps: float | None = None
    mesh_plink: str | None = None  # e.g. "ESTAB", "OPN_SNT"


class RFState(BaseModel):
    iface: str
    type: str | None = None       # mp, AP, managed...
    channel: int | None = None
    freq_mhz: int | None = None
    txpower_dbm: float | None = None
    width_mhz: int | None = None
    reg_country: str
    reg_dfs_state: str | None = None


class APClient(BaseModel):
    mac: str
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    signal_dbm: int | None = None
    connected_time_s: int | None = None
    passpoint: bool = False


class RegRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    country: str = Field(..., pattern=r"^[A-Z]{2}$")
    reason: str = Field(..., min_length=4)
