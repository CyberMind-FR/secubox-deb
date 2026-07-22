# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — host-side serial↔MQTT bridge (grid-policy driven)."""
from __future__ import annotations
import json
import logging
from typing import Callable
from .config import Config
from .gridpolicy import targets_for
from .model import Packet

_log = logging.getLogger("secubox.meshtastic.bridge")


class Bridge:
    def __init__(self, cfg: Config, mqtt_factory: Callable[[str], object]) -> None:
        self.cfg = cfg
        self._factory = mqtt_factory
        self._clients: dict[str, object] = {}

    def start(self) -> None:
        for tgt, bc in (("shared", self.cfg.shared_grid), ("on", self.cfg.on_grid)):
            if bc is None or (tgt == "on" and not bc.enabled):
                continue
            host, _, port = bc.broker.partition(":")
            try:
                port_num = int(port) if port else 1883
            except ValueError:
                port_num = 1883
            cli = self._factory(tgt)
            try:
                cli.connect(host, port_num)
            except Exception as exc:
                # A configured broker that is DOWN at startup (e.g. the opt-in
                # private mosquitto not yet running) must NOT crash the daemon —
                # skip this target; it can be reconnected when the broker is up.
                _log.warning("bridge: %s broker %s:%s unreachable at start (%s); skipping",
                             tgt, host, port_num, exc)
                continue
            self._clients[tgt] = cli

    def publish(self, channel_name: str, p: Packet) -> None:
        for tgt in targets_for(channel_name, self.cfg):
            cli = self._clients.get(tgt)
            if cli is None:
                continue
            topic = f"msh/{self.cfg.region}/2/e/{channel_name}/{p.from_id}"
            cli.publish(topic, json.dumps(vars(p)))

    def stop(self) -> None:
        for cli in self._clients.values():
            try: cli.disconnect()
            except Exception: pass
        self._clients.clear()
