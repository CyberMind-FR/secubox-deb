# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — daemon engine (wires radio/cache/passive/bridge)."""
from __future__ import annotations
import logging
import threading
import time
from pathlib import Path

from .model import MeshState, parse_packet
from .gridpolicy import nft_egress_rules  # noqa: F401  (used by ctl; re-export locus)

log = logging.getLogger("secubox.meshtastic.daemon")

CONFIG_PATH = Path("/etc/secubox/meshtastic.toml")
CACHE_PATH = Path("/var/cache/secubox/meshtastic/state.json")
SOCKET_PATH = "/run/secubox/meshtastic.sock"
CACHE_REFRESH_INTERVAL = 60.0


class Engine:
    def __init__(self, cfg, radio, cache, capture, bridge, clock=time.time) -> None:
        self.cfg, self.radio, self.cache = cfg, radio, cache
        self.capture, self.bridge, self.clock = capture, bridge, clock
        self.state = MeshState()
        self.present = radio is not None

    def channel_name(self, idx: int) -> str:
        if 0 <= idx < len(self.cfg.channels):
            return self.cfg.channels[idx].name
        return str(idx)

    def decrypted_for(self, idx: int) -> bool:
        return (0 <= idx < len(self.cfg.channels)
                and bool(self.cfg.channels[idx].psk_secret))

    def on_receive(self, pkt: dict) -> None:
        now = self.clock()
        p = parse_packet(pkt)
        self.state.apply_packet(p, now)
        if p.portnum == "NODEINFO_APP" and p.decoded:
            self.state.apply_nodeinfo({"num": pkt.get("from", 0), "user": p.decoded}, now)
        if self.cfg.mode in ("passive-listener", "both"):
            self.capture.record(p, now, self.decrypted_for(p.channel))
        if self.cfg.mode in ("active-node", "both"):
            self.bridge.publish(self.channel_name(p.channel), p)
        self.cache.update(self.snapshot())

    def snapshot(self) -> dict:
        d = self.state.to_dict()
        d.update({
            "radio": "present" if self.present else "absent",
            "mode": self.cfg.mode,
            "grids": {c.name: list(c.grid) for c in self.cfg.channels},
            "census": self.capture.census(),
            "channel_stats": {str(k): v for k, v in self.capture.channel_stats().items()},
        })
        return d


class _PahoAdapter:
    """Thin adapter so Bridge only needs .connect/.publish/.disconnect.

    Wraps a real paho-mqtt client. Instantiated lazily by main() so the
    test suite (which injects FakeMqtt directly) never needs paho installed.
    """

    def __init__(self, client) -> None:
        self._client = client

    def connect(self, host: str, port: int) -> None:
        self._client.connect(host, port)
        self._client.loop_start()

    def publish(self, topic: str, payload: str) -> None:
        self._client.publish(topic, payload)

    def disconnect(self) -> None:
        try:
            self._client.loop_stop()
        except Exception:
            pass
        self._client.disconnect()


def _mqtt_factory(key: str):
    """Build a paho-backed mqtt client for Bridge. Imports paho lazily so
    daemon.py stays importable (and the test suite never needs paho) when
    the library is absent — the bridge simply won't connect for that grid."""
    try:
        import paho.mqtt.client as paho_client
    except Exception:
        log.warning("paho-mqtt unavailable — %s grid bridge disabled", key)
        return _NullMqtt()
    client_id = f"secubox-meshtastic-{key}"
    return _PahoAdapter(paho_client.Client(client_id=client_id))


class _NullMqtt:
    """No-op mqtt client used when paho-mqtt is not installed."""

    def connect(self, host: str, port: int) -> None:
        pass

    def publish(self, topic: str, payload: str) -> None:
        pass

    def disconnect(self) -> None:
        pass


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    from .config import load
    from .radio import open_serial
    from .bridge import Bridge
    from .passive import PassiveCapture
    from .cache import StateCache

    cfg = load(CONFIG_PATH)

    radio = open_serial(cfg.serial)
    present = radio is not None
    if not present:
        log.warning("radio absent (serial=%s) — daemon runs cache/passive/bridge only", cfg.serial)

    bridge = Bridge(cfg, _mqtt_factory)
    bridge.start()

    capture = PassiveCapture(cfg.passive.packet_log)
    cache = StateCache(CACHE_PATH)

    engine = Engine(cfg, radio, cache, capture, bridge)

    if radio is not None:
        radio.on("receive", engine.on_receive)

    stop = threading.Event()

    try:
        from . import web  # Task 10: replace with uvicorn UDS serve of api.web
    except ImportError:
        web = None

    if web is not None:
        # Task 10: replace with uvicorn UDS serve of api.web
        import uvicorn
        app = web.create_app(engine)
        cache.start_refresh(engine.snapshot, CACHE_REFRESH_INTERVAL, stop)
        try:
            uvicorn.run(app, uds=SOCKET_PATH, log_level="info")
        finally:
            stop.set()
            bridge.stop()
            if radio is not None:
                radio.close()
    else:
        # Task 10: replace with uvicorn UDS serve of api.web
        log.info("api.web not available yet — running cache-refresh only, no webui")
        cache.start_refresh(engine.snapshot, CACHE_REFRESH_INTERVAL, stop)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            bridge.stop()
            if radio is not None:
                radio.close()


if __name__ == "__main__":
    main()
