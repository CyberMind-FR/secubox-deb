# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — per-channel grid routing + nft egress allow-list."""
from __future__ import annotations
from .config import Config


def targets_for(channel_name: str, cfg: Config) -> set[str]:
    """Return the set of grids ("shared", "on") that a channel bridges to.

    A channel bridges to "shared" if its grid contains "shared" and shared_grid is configured.
    A channel bridges to "on" if its grid contains "on" AND on_grid is configured AND on_grid.enabled.
    """
    ch = next((c for c in cfg.channels if c.name == channel_name), None)
    if ch is None:
        return set()
    out: set[str] = set()
    if "shared" in ch.grid and cfg.shared_grid is not None:
        out.add("shared")
    if "on" in ch.grid and cfg.on_grid is not None and cfg.on_grid.enabled:
        out.add("on")
    return out


def nft_egress_rules(cfg: Config) -> list[str]:
    """Allow rules for ENABLED on-grid brokers only. Empty => DEFAULT DROP holds.
    Rendered into the operator drop-in the ctl installs."""
    if not (cfg.on_grid and cfg.on_grid.enabled):
        return []
    host, _, port = cfg.on_grid.broker.partition(":")
    port = port or "8883"
    return [f'# secubox-meshtastic on-grid egress (broker {cfg.on_grid.broker})',
            f'ip daddr {host} tcp dport {port} accept comment "meshtastic-on-grid"']
