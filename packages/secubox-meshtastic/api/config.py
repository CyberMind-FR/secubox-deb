# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — config loader (/etc/secubox/meshtastic.toml)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

MODES = ("active-node", "passive-listener", "both")
GRIDS = ("off", "shared", "on")
ROLES = ("CLIENT", "CLIENT_MUTE", "ROUTER", "REPEATER", "TRACKER", "SENSOR")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class ChannelCfg:
    name: str
    grid: tuple[str, ...]
    psk_secret: str


@dataclass(frozen=True)
class BrokerCfg:
    broker: str
    enabled: bool = False


@dataclass(frozen=True)
class PassiveCfg:
    role: str = "CLIENT_MUTE"
    packet_log: str = "/var/log/secubox/meshtastic/packets.jsonl"


@dataclass(frozen=True)
class Config:
    mode: str = "active-node"
    region: str = "EU_868"
    serial: str = "auto"
    channels: list[ChannelCfg] = field(default_factory=list)
    shared_grid: BrokerCfg | None = None
    on_grid: BrokerCfg | None = None
    passive: PassiveCfg = field(default_factory=PassiveCfg)


def load(path: Path) -> Config:
    path = Path(path)
    if not path.exists():
        return Config()
    try:
        d = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    mode = d.get("mode", "active-node")
    if mode not in MODES:
        raise ConfigError(f"mode invalide: {mode!r} (attendu {MODES})")
    channels = []
    for ch in d.get("channel", []):
        grid = tuple(ch.get("grid", ()))
        bad = [g for g in grid if g not in GRIDS]
        if bad:
            raise ConfigError(f"grid inconnu {bad} (attendu {GRIDS})")
        channels.append(ChannelCfg(ch["name"], grid, ch.get("psk_secret", "")))
    passive = d.get("passive", {})
    role = passive.get("role", "CLIENT_MUTE")
    if role not in ROLES:
        raise ConfigError(f"role invalide: {role!r}")

    def _broker(sec):
        if not sec:
            return None
        return BrokerCfg(sec["broker"], bool(sec.get("enabled", False)))

    return Config(
        mode=mode,
        region=d.get("region", "EU_868"),
        serial=d.get("serial", "auto"),
        channels=channels,
        shared_grid=_broker(d.get("shared_grid")),
        on_grid=_broker(d.get("on_grid")),
        passive=PassiveCfg(role, passive.get("packet_log", PassiveCfg().packet_log)),
    )
