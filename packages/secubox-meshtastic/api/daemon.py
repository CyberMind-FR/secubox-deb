# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — daemon engine (wires radio/cache/passive/bridge)."""
from __future__ import annotations
import json
import logging
import subprocess
import threading
import time
from pathlib import Path

from .model import MeshState, parse_packet

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
        # connect_async (not connect): a broker that is DOWN at startup must not
        # raise/crash the daemon — loop_start's background thread establishes and
        # auto-reconnects the connection when the broker becomes reachable.
        self._client.connect_async(host, port)
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


def _ctl_cb(verb: str, **kwargs) -> dict:
    """webui -> ctl delegate for `web.create_app`'s `ctl_cb` (see
    secubox-profiles/api/web.py's `_run_ctl_json_argv` for the pattern this
    mirrors — same `sudo -n systemd-run --wait --pipe --collect --quiet`
    shape, run synchronously since daemon.main() has no asyncio loop to
    offload onto). `secubox-meshtasticctl` argv is positional-argument based
    (see api/ctl.py argparse: `set-mode <mode>`, `set-grid <channel> --grid
    <csv>`) and today prints plain text, not a `--json` report — so a
    successful (rc=0) run is reported as `{"status": "applied", ...}` from
    stdout, and only a genuine JSON report (if the ctl ever grows one) short-
    circuits that. Web-side validation (config.MODES / config.GRIDS, see
    api/web.py) has already refused bad values before this is ever called."""
    argv = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe",
            "--collect", "--quiet", "/usr/sbin/secubox-meshtasticctl", verb]
    if verb == "set-mode":
        argv.append(str(kwargs["mode"]))
    elif verb == "set-grid":
        argv.append(str(kwargs["channel"]))
        argv += ["--grid", ",".join(kwargs["grid"])]
    else:
        return {"status": "error", "stderr": f"ctl verb inconnu: {verb}"}

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except Exception as exc:  # sudo/systemd-run itself missing, timeout, ...
        return {"status": "error", "stderr": str(exc)}

    try:
        report = json.loads(proc.stdout)
        if isinstance(report, dict) and "status" in report:
            return report
    except ValueError:
        pass

    if proc.returncode == 0:
        return {"status": "applied", "verb": verb, "output": proc.stdout.strip()}
    return {"status": "error", "stderr": (proc.stderr or proc.stdout).strip()[:300]}


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
        from . import web
        import uvicorn
    except ImportError:
        web = None

    if web is not None:
        def send_cb(channel: int, text: str) -> dict:
            if engine.radio is None:
                return {"status": "radio-absent"}
            engine.radio.send_text(text, channel)
            return {"status": "sent", "channel": channel}

        app = web.create_app(engine.cache, send_cb, _ctl_cb)
        cache.start_refresh(engine.snapshot, CACHE_REFRESH_INTERVAL, stop)
        try:
            uvicorn.run(app, uds=SOCKET_PATH, log_level="warning")
        finally:
            stop.set()
            bridge.stop()
            if radio is not None:
                radio.close()
    else:
        log.info("api.web/uvicorn not available — running cache-refresh only, no webui")
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
