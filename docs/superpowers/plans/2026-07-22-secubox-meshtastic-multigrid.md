<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-meshtastic — Multi-Grid LoRa Node + Passive Listener — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `secubox-meshtastic`, a native-host SecuBox module that drives a USB Meshtastic device as a multi-grid mesh node (off-grid RF / private shared-grid over MirrorNet / opt-in public MQTT) plus an optional passive `CLIENT_MUTE` RF listener feeding the SOC.

**Architecture:** A Python daemon (`secubox-meshtasticd`) owns the serial device behind a thin `RadioInterface` (real `meshtastic.SerialInterface` in prod, `MockRadio` in tests) and maintains mesh state behind the double-cache pattern. A host-side `Bridge` republishes packets to MQTT brokers per a per-channel `GridPolicy`. A FastAPI webui reads the cache and delegates privileged actions to a root `secubox-meshtasticctl`. No device is required to run — the module degrades to a `radio: absent` state.

**Tech Stack:** Python 3.11, `meshtastic` (pip) + `paho-mqtt` (pip), FastAPI/uvicorn, mosquitto (private broker), nftables (egress), vanilla-JS webui. Native systemd module (not LXC).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-22-secubox-meshtastic-multigrid-design.md`.
- Band **EU868**; device region `EU_868`.
- **Host-side MQTT bridging only** — never device-firmware MQTT.
- Public egress: `nft` DEFAULT DROP + explicit broker allow + WAF/mitmproxy; **off by default, opt-in per channel**.
- Dedicated user **`secubox-meshtastic`** (in `dialout`); privileged config only via the audited `secubox-meshtasticctl` (webui→ctl); secrets `0600` under `/etc/secubox/secrets/meshtastic/`.
- **Graceful no-device state**: run + serve + persist config with `radio: absent`; never crash on a missing device.
- **Offline-clean webui**: no external tile/font/CDN dependency.
- **Tests never import `meshtastic` or open a real serial port** — parse plain packet dicts and inject `MockRadio` / fake MQTT clients.
- SPDX header on every Python/Bash file (`scripts/license-headers.py` verifies): `LicenseRef-CMSD-1.0`, `Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>`.
- Double-cache = a `threading.Thread(target=refresh_*)` background refresher + in-memory dict guarded read (the idiom the dashboard-cache lint recognizes).
- Debian: `debian/compat` = 13, `Standards-Version: 4.6.2`, version `0.1.0-1~bookworm1`.
- Run tests per-directory: `cd packages/secubox-meshtastic && python -m pytest tests/ -q`.

## File Structure

```
packages/secubox-meshtastic/
├── api/
│   ├── __init__.py
│   ├── config.py       # load/validate /etc/secubox/meshtastic.toml → Config dataclass
│   ├── model.py        # Node, Packet, ChannelState, MeshState + parse_packet(dict)->Packet
│   ├── cache.py        # StateCache: in-mem + state.json + background refresh thread
│   ├── radio.py        # RadioInterface protocol, SerialRadio (real), MockRadio (tests)
│   ├── gridpolicy.py   # bridge routing decisions + nft egress allow-list generation
│   ├── passive.py      # PassiveCapture: packet-log JSONL + heard-node census + channel stats
│   ├── bridge.py       # host-side serial↔MQTT bridge (paho-mqtt), grid-policy driven
│   ├── daemon.py       # secubox-meshtasticd: wires radio+cache+bridge+passive; control API
│   ├── web.py          # FastAPI: read cache, delegate actions to daemon/ctl
│   └── ctl.py          # secubox-meshtasticctl: privileged (psk/region/role/grid/nft egress)
├── sbin/
│   ├── secubox-meshtasticd
│   └── secubox-meshtasticctl
├── conf/meshtastic.toml.example
├── www/meshtastic/index.html
├── nginx/meshtastic.conf
├── menu.d/71-meshtastic.json
├── systemd/secubox-meshtasticd.service
├── sudoers.d/secubox-meshtastic
├── debian/{control,compat,rules,changelog,install,postinst,prerm,secubox-meshtasticd.service}
├── tests/{conftest.py,test_config,test_model,test_cache,test_radio,test_gridpolicy,
│          test_passive,test_bridge,test_daemon,test_ctl,test_web}.py
└── README.md
```

---

### Task 1: Package scaffold + config loader

**Files:**
- Create: `packages/secubox-meshtastic/api/__init__.py`, `api/config.py`, `tests/conftest.py`, `tests/test_config.py`, `conf/meshtastic.toml.example`, `debian/{control,compat,changelog,rules}`.

**Interfaces:**
- Produces: `config.load(path: Path) -> Config`; `Config` dataclass with `.mode:str`, `.region:str`, `.serial:str`, `.channels:list[ChannelCfg]`, `.shared_grid:BrokerCfg|None`, `.on_grid:BrokerCfg|None`, `.passive:PassiveCfg`. `ChannelCfg(name:str, grid:tuple[str,...], psk_secret:str)`. `BrokerCfg(broker:str, enabled:bool)`. `PassiveCfg(role:str, packet_log:str)`. `config.ConfigError(Exception)`.

- [ ] **Step 1: scaffold dirs + SPDX'd empty `api/__init__.py`**

```bash
mkdir -p packages/secubox-meshtastic/{api,tests,conf,debian}
printf '# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n' > packages/secubox-meshtastic/api/__init__.py
```

- [ ] **Step 2: write `tests/conftest.py`** (adds `api` to path)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
```

- [ ] **Step 3: write failing `tests/test_config.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pytest

_TOML = """
mode = "both"
region = "EU_868"
serial = "auto"
[[channel]]
name = "family"
grid = ["off", "shared"]
psk_secret = "family-psk"
[shared_grid]
broker = "10.10.0.1:1883"
[on_grid]
broker = "mqtt.example.org:8883"
enabled = false
[passive]
role = "CLIENT_MUTE"
packet_log = "/var/log/secubox/meshtastic/packets.jsonl"
"""

def test_load_parses_all_sections(tmp_path):
    from api import config
    p = tmp_path / "meshtastic.toml"; p.write_text(_TOML)
    c = config.load(p)
    assert c.mode == "both" and c.region == "EU_868"
    assert c.channels[0].name == "family" and c.channels[0].grid == ("off", "shared")
    assert c.shared_grid.broker == "10.10.0.1:1883"
    assert c.on_grid.enabled is False
    assert c.passive.role == "CLIENT_MUTE"

def test_rejects_bad_mode(tmp_path):
    from api import config
    p = tmp_path / "m.toml"; p.write_text('mode="turbo"\nregion="EU_868"\n')
    with pytest.raises(config.ConfigError):
        config.load(p)

def test_rejects_unknown_grid(tmp_path):
    from api import config
    p = tmp_path / "m.toml"
    p.write_text('mode="active-node"\nregion="EU_868"\n[[channel]]\nname="x"\ngrid=["warp"]\npsk_secret="x"\n')
    with pytest.raises(config.ConfigError):
        config.load(p)

def test_missing_file_yields_safe_default(tmp_path):
    from api import config
    c = config.load(tmp_path / "nope.toml")
    assert c.mode == "active-node" and c.channels == [] and c.on_grid is None
```

- [ ] **Step 4: run — FAIL** (`ModuleNotFoundError: api.config`)

Run: `cd packages/secubox-meshtastic && python -m pytest tests/test_config.py -q`

- [ ] **Step 5: implement `api/config.py`**

```python
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
        mode=mode, region=d.get("region", "EU_868"), serial=d.get("serial", "auto"),
        channels=channels, shared_grid=_broker(d.get("shared_grid")),
        on_grid=_broker(d.get("on_grid")),
        passive=PassiveCfg(role, passive.get("packet_log", PassiveCfg().packet_log)),
    )
```

- [ ] **Step 6: run — PASS**; write `conf/meshtastic.toml.example` (copy the spec §10 TOML block).

- [ ] **Step 7: write `debian/control`, `debian/compat` (`13`), `debian/changelog` (`0.1.0-1~bookworm1`), minimal `debian/rules` (`#!/usr/bin/make -f` + `%:\n\tdh $@`).** `control`: `Package: secubox-meshtastic`, `Depends: python3, python3-paho-mqtt, secubox-core`, `Standards-Version: 4.6.2`.

- [ ] **Step 8: commit**

```bash
git add packages/secubox-meshtastic && git commit -m "feat(meshtastic): package scaffold + config loader (ref #897)"
```

---

### Task 2: Mesh data model + packet parser

**Files:** Create `api/model.py`, `tests/test_model.py`.

**Interfaces:**
- Produces: `model.parse_packet(pkt: dict) -> Packet`; `Packet(from_id:str, to_id:str, channel:int, portnum:str, decoded:dict|None, rssi:int|None, snr:float|None, hop:int|None, ts:float)`; `Node(id:str, short:str, long:str, role:str, pos:tuple|None, battery:int|None, rssi:int|None, snr:float|None, first_heard:float, last_heard:float)`; `MeshState` with `.apply_packet(Packet, now:float)`, `.apply_nodeinfo(dict, now)`, `.to_dict()`.

The parser consumes the `meshtastic` pubsub packet dict shape (`{'from':.., 'to':.., 'channel':.., 'decoded':{'portnum':.., ...}, 'rxRssi':.., 'rxSnr':.., 'hopLimit':..}`) — **tests build these dicts directly, no `meshtastic` import.**

- [ ] **Step 1: failing `tests/test_model.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
def _pkt(**kw):
    base = {"from": 0x11, "to": 0xffffffff, "channel": 0,
            "decoded": {"portnum": "TEXT_MESSAGE_APP", "text": "hi"},
            "rxRssi": -95, "rxSnr": 6.5, "hopLimit": 3}
    base.update(kw); return base

def test_parse_packet_fields():
    from api.model import parse_packet
    p = parse_packet(_pkt())
    assert p.from_id == "!00000011" and p.portnum == "TEXT_MESSAGE_APP"
    assert p.rssi == -95 and p.snr == 6.5 and p.decoded["text"] == "hi"

def test_meshstate_census_updates_last_heard():
    from api.model import MeshState, parse_packet
    st = MeshState()
    st.apply_packet(parse_packet(_pkt()), now=100.0)
    st.apply_packet(parse_packet(_pkt()), now=200.0)
    node = st.to_dict()["nodes"][0]
    assert node["id"] == "!00000011" and node["first_heard"] == 100.0 and node["last_heard"] == 200.0

def test_text_message_lands_in_channel_log():
    from api.model import MeshState, parse_packet
    st = MeshState()
    st.apply_packet(parse_packet(_pkt(channel=1)), now=1.0)
    assert st.to_dict()["messages_by_channel"]["1"][0]["text"] == "hi"

def test_nodeinfo_sets_names_and_role():
    from api.model import MeshState
    st = MeshState()
    st.apply_nodeinfo({"num": 0x22, "user": {"shortName": "AB", "longName": "Alpha", "role": "CLIENT_MUTE"}}, now=5.0)
    n = st.to_dict()["nodes"][0]
    assert n["id"] == "!00000022" and n["short"] == "AB" and n["role"] == "CLIENT_MUTE"
```

- [ ] **Step 2: run — FAIL.** Run: `python -m pytest tests/test_model.py -q`

- [ ] **Step 3: implement `api/model.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — mesh state model + packet parser."""
from __future__ import annotations
from dataclasses import dataclass, field


def _nid(n) -> str:
    if isinstance(n, str):
        return n if n.startswith("!") else f"!{int(n):08x}"
    return f"!{int(n):08x}"


@dataclass
class Packet:
    from_id: str
    to_id: str
    channel: int
    portnum: str
    decoded: dict | None
    rssi: int | None
    snr: float | None
    hop: int | None
    ts: float = 0.0


def parse_packet(pkt: dict) -> Packet:
    dec = pkt.get("decoded") or {}
    return Packet(
        from_id=_nid(pkt.get("from", 0)),
        to_id=_nid(pkt.get("to", 0xffffffff)),
        channel=int(pkt.get("channel", 0)),
        portnum=str(dec.get("portnum", "UNKNOWN")),
        decoded=dec or None,
        rssi=pkt.get("rxRssi"),
        snr=pkt.get("rxSnr"),
        hop=pkt.get("hopLimit"),
        ts=float(pkt.get("rxTime", 0.0)),
    )


@dataclass
class Node:
    id: str
    short: str = ""
    long: str = ""
    role: str = ""
    pos: tuple | None = None
    battery: int | None = None
    rssi: int | None = None
    snr: float | None = None
    first_heard: float = 0.0
    last_heard: float = 0.0


class MeshState:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.messages: dict[int, list[dict]] = {}

    def _touch(self, nid: str, now: float) -> Node:
        n = self.nodes.get(nid)
        if n is None:
            n = Node(id=nid, first_heard=now)
            self.nodes[nid] = n
        n.last_heard = now
        return n

    def apply_packet(self, p: Packet, now: float) -> None:
        n = self._touch(p.from_id, now)
        if p.rssi is not None:
            n.rssi = p.rssi
        if p.snr is not None:
            n.snr = p.snr
        if p.portnum == "POSITION_APP" and p.decoded:
            lat, lon = p.decoded.get("latitude"), p.decoded.get("longitude")
            if lat is not None and lon is not None:
                n.pos = (lat, lon)
        if p.portnum == "TELEMETRY_APP" and p.decoded:
            batt = (p.decoded.get("deviceMetrics") or {}).get("batteryLevel")
            if batt is not None:
                n.battery = batt
        if p.portnum == "TEXT_MESSAGE_APP" and p.decoded:
            self.messages.setdefault(p.channel, []).append(
                {"from": p.from_id, "text": p.decoded.get("text", ""), "ts": now})

    def apply_nodeinfo(self, info: dict, now: float) -> None:
        nid = _nid(info.get("num", 0))
        n = self._touch(nid, now)
        u = info.get("user") or {}
        n.short = u.get("shortName", n.short)
        n.long = u.get("longName", n.long)
        n.role = u.get("role", n.role)

    def to_dict(self) -> dict:
        return {
            "nodes": [vars(n) for n in self.nodes.values()],
            "messages_by_channel": {str(k): v for k, v in self.messages.items()},
        }
```

- [ ] **Step 4: run — PASS. Step 5: commit** `feat(meshtastic): mesh state model + packet parser`.

---

### Task 3: StateCache (double-cache pattern)

**Files:** Create `api/cache.py`, `tests/test_cache.py`.

**Interfaces:**
- Produces: `StateCache(path: Path)` with `.update(state_dict: dict)`, `.get() -> dict`, `.start_refresh(producer: Callable[[], dict], interval: float, stop: threading.Event)` (spawns `threading.Thread(target=self._refresh_loop, ...)` — the lint-recognized idiom). `.get()` returns the in-mem dict if warm, else reads `path`, else `{"radio": "absent"}`.

- [ ] **Step 1: failing `tests/test_cache.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json

def test_update_then_get_roundtrips_and_persists(tmp_path):
    from api.cache import StateCache
    c = StateCache(tmp_path / "state.json")
    c.update({"radio": "present", "nodes": []})
    assert c.get()["radio"] == "present"
    assert json.loads((tmp_path / "state.json").read_text())["radio"] == "present"

def test_cold_get_reads_file(tmp_path):
    from api.cache import StateCache
    (tmp_path / "state.json").write_text('{"radio":"present","nodes":[1]}')
    assert StateCache(tmp_path / "state.json").get()["nodes"] == [1]

def test_cold_get_no_file_is_radio_absent(tmp_path):
    from api.cache import StateCache
    assert StateCache(tmp_path / "state.json").get()["radio"] == "absent"

def test_refresh_thread_calls_producer(tmp_path):
    import threading, time
    from api.cache import StateCache
    c = StateCache(tmp_path / "state.json")
    stop = threading.Event()
    c.start_refresh(lambda: {"radio": "present", "n": 1}, interval=0.01, stop=stop)
    time.sleep(0.05); stop.set()
    assert c.get()["n"] == 1
```

- [ ] **Step 2: run — FAIL. Step 3: implement `api/cache.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — double-cache (in-mem + state.json + bg thread)."""
from __future__ import annotations
import json, os, tempfile, threading
from pathlib import Path
from typing import Callable


class StateCache:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._mem: dict = {}

    def update(self, state: dict) -> None:
        with self._lock:
            self._mem = dict(state)
        self._write_atomic(state)

    def get(self) -> dict:
        with self._lock:
            if self._mem:
                return dict(self._mem)
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"radio": "absent"}

    def start_refresh(self, producer: Callable[[], dict], interval: float,
                      stop: threading.Event) -> None:
        threading.Thread(target=self._refresh_loop, args=(producer, interval, stop),
                         daemon=True).start()

    def _refresh_loop(self, producer, interval, stop) -> None:
        while not stop.is_set():
            try:
                self.update(producer())
            except Exception:
                pass
            stop.wait(interval)

    def _write_atomic(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(tmp, self.path)
        except BaseException:
            try: os.unlink(tmp)
            except FileNotFoundError: pass
            raise
```

- [ ] **Step 4: run — PASS. Step 5: commit** `feat(meshtastic): StateCache double-cache`.

---

### Task 4: RadioInterface + MockRadio + SerialRadio

**Files:** Create `api/radio.py`, `tests/test_radio.py`.

**Interfaces:**
- Produces: `radio.RadioInterface` (Protocol: `.on(event:str, cb)`, `.send_text(text:str, channel:int)`, `.close()`); `radio.MockRadio()` with `.emit(event, payload)` for tests; `radio.open_serial(dev:str) -> RadioInterface | None` (returns `None` when no device — the `radio: absent` path; imports `meshtastic` lazily so tests never import it).

- [ ] **Step 1: failing `tests/test_radio.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
def test_mock_radio_dispatches_events():
    from api.radio import MockRadio
    r = MockRadio(); seen = []
    r.on("receive", lambda pkt: seen.append(pkt))
    r.emit("receive", {"from": 1})
    assert seen == [{"from": 1}]

def test_mock_radio_records_sent_text():
    from api.radio import MockRadio
    r = MockRadio(); r.send_text("hello", channel=2)
    assert r.sent == [("hello", 2)]

def test_open_serial_absent_device_returns_none(tmp_path):
    from api.radio import open_serial
    assert open_serial(str(tmp_path / "no-such-tty")) is None
```

- [ ] **Step 2: run — FAIL. Step 3: implement `api/radio.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — radio interface (real serial + test mock).

The real SerialRadio imports `meshtastic` LAZILY inside open_serial() so the
test suite (which uses MockRadio) never needs the library or a serial port."""
from __future__ import annotations
import os
from typing import Callable, Protocol


class RadioInterface(Protocol):
    def on(self, event: str, cb: Callable) -> None: ...
    def send_text(self, text: str, channel: int = 0) -> None: ...
    def close(self) -> None: ...


class MockRadio:
    def __init__(self) -> None:
        self._cbs: dict[str, list[Callable]] = {}
        self.sent: list[tuple[str, int]] = []

    def on(self, event: str, cb: Callable) -> None:
        self._cbs.setdefault(event, []).append(cb)

    def emit(self, event: str, payload) -> None:
        for cb in self._cbs.get(event, []):
            cb(payload)

    def send_text(self, text: str, channel: int = 0) -> None:
        self.sent.append((text, channel))

    def close(self) -> None:
        pass


def open_serial(dev: str) -> RadioInterface | None:
    """Return a live radio, or None if the device is absent (radio: absent)."""
    if dev != "auto" and not os.path.exists(dev):
        return None
    try:
        from meshtastic.serial_interface import SerialInterface  # lazy
        from pubsub import pub
    except Exception:
        return None
    try:
        iface = SerialInterface(devPath=None if dev == "auto" else dev)
    except Exception:
        return None
    return _SerialRadio(iface, pub)


class _SerialRadio:
    def __init__(self, iface, pub) -> None:
        self._iface, self._pub = iface, pub

    def on(self, event: str, cb: Callable) -> None:
        topic = {"receive": "meshtastic.receive",
                 "node": "meshtastic.node.updated",
                 "connection": "meshtastic.connection.established"}[event]
        self._pub.subscribe(lambda packet=None, interface=None, **kw: cb(packet or {}), topic)

    def send_text(self, text: str, channel: int = 0) -> None:
        self._iface.sendText(text, channelIndex=channel)

    def close(self) -> None:
        try: self._iface.close()
        except Exception: pass
```

- [ ] **Step 4: run — PASS. Step 5: commit** `feat(meshtastic): RadioInterface + MockRadio + lazy serial`.

---

### Task 5: GridPolicy — bridge routing + nft egress allow-list

**Files:** Create `api/gridpolicy.py`, `tests/test_gridpolicy.py`.

**Interfaces:**
- Consumes: `config.Config`, `config.ChannelCfg`.
- Produces: `gridpolicy.targets_for(channel_name:str, cfg:Config) -> set[str]` (subset of `{"shared","on"}` a channel bridges to); `gridpolicy.nft_egress_rules(cfg:Config) -> list[str]` (allow rules for enabled on-grid brokers only; empty when none enabled — DEFAULT DROP holds).

- [ ] **Step 1: failing `tests/test_gridpolicy.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from api.config import Config, ChannelCfg, BrokerCfg

def _cfg(grid, on_enabled=False):
    return Config(channels=[ChannelCfg("c", tuple(grid), "psk")],
                  shared_grid=BrokerCfg("10.10.0.1:1883"),
                  on_grid=BrokerCfg("mqtt.x.org:8883", on_enabled))

def test_offgrid_only_bridges_nowhere():
    from api.gridpolicy import targets_for
    assert targets_for("c", _cfg(["off"])) == set()

def test_shared_and_on_targets():
    from api.gridpolicy import targets_for
    assert targets_for("c", _cfg(["off", "shared", "on"], on_enabled=True)) == {"shared", "on"}

def test_on_target_dropped_when_broker_disabled():
    from api.gridpolicy import targets_for
    assert targets_for("c", _cfg(["off", "on"], on_enabled=False)) == set()

def test_nft_rules_empty_when_no_on_grid():
    from api.gridpolicy import nft_egress_rules
    assert nft_egress_rules(_cfg(["off"], on_enabled=False)) == []

def test_nft_rules_allow_only_enabled_broker():
    from api.gridpolicy import nft_egress_rules
    rules = nft_egress_rules(_cfg(["on"], on_enabled=True))
    assert any("8883" in r and "mqtt.x.org" in r and "accept" in r for r in rules)
```

- [ ] **Step 2: run — FAIL. Step 3: implement `api/gridpolicy.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — per-channel grid routing + nft egress allow-list."""
from __future__ import annotations
from .config import Config


def targets_for(channel_name: str, cfg: Config) -> set[str]:
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
```

*(Note: host may be a name; the ctl resolves it or accepts an IP. Name-vs-IP resolution handled in Task 9 when the ctl renders the drop-in; the rule string carries the configured host verbatim.)*

- [ ] **Step 4: run — PASS. Step 5: commit** `feat(meshtastic): grid policy + nft egress allow-list`.

---

### Task 6: PassiveCapture — packet log + census + channel stats

**Files:** Create `api/passive.py`, `tests/test_passive.py`.

**Interfaces:**
- Consumes: `model.Packet`.
- Produces: `passive.PassiveCapture(log_path: Path)` with `.record(p: Packet, now: float, decrypted: bool)`, `.census() -> list[dict]`, `.channel_stats() -> dict[int, dict]`. `.record` appends one JSON line per packet (metadata always; payload only when `decrypted`).

- [ ] **Step 1: failing `tests/test_passive.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from api.model import Packet

def _p(fr="!00000001", ch=0, port="TEXT_MESSAGE_APP", dec=None):
    return Packet(fr, "!ffffffff", ch, port, dec, -90, 5.0, 3, 0.0)

def test_record_appends_metadata_line(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "packets.jsonl")
    cap.record(_p(dec={"text": "secret"}), now=1.0, decrypted=False)
    line = json.loads((tmp_path / "packets.jsonl").read_text().strip())
    assert line["from"] == "!00000001" and line["portnum"] == "TEXT_MESSAGE_APP"
    assert "text" not in json.dumps(line)     # payload withheld when not decrypted

def test_record_includes_payload_when_decrypted(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "packets.jsonl")
    cap.record(_p(dec={"text": "hi"}), now=1.0, decrypted=True)
    assert "hi" in (tmp_path / "packets.jsonl").read_text()

def test_census_tracks_all_heard_nodes(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "p.jsonl")
    cap.record(_p(fr="!00000001"), now=1.0, decrypted=True)
    cap.record(_p(fr="!00000002"), now=2.0, decrypted=True)
    cap.record(_p(fr="!00000001"), now=3.0, decrypted=True)
    ids = {c["id"]: c for c in cap.census()}
    assert set(ids) == {"!00000001", "!00000002"}
    assert ids["!00000001"]["first_heard"] == 1.0 and ids["!00000001"]["last_heard"] == 3.0

def test_channel_stats_count_per_channel(tmp_path):
    from api.passive import PassiveCapture
    cap = PassiveCapture(tmp_path / "p.jsonl")
    cap.record(_p(ch=0), 1.0, True); cap.record(_p(ch=1), 2.0, True); cap.record(_p(ch=1), 3.0, True)
    assert cap.channel_stats()[1]["packets"] == 2
```

- [ ] **Step 2: run — FAIL. Step 3: implement `api/passive.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — passive capture (packet log + census + stats)."""
from __future__ import annotations
import json
from pathlib import Path
from .model import Packet


class PassiveCapture:
    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)
        self._census: dict[str, dict] = {}
        self._chan: dict[int, dict] = {}

    def record(self, p: Packet, now: float, decrypted: bool) -> None:
        line = {"ts": now, "from": p.from_id, "to": p.to_id, "channel": p.channel,
                "portnum": p.portnum, "rssi": p.rssi, "snr": p.snr, "hop": p.hop,
                "decrypted": decrypted}
        if decrypted and p.decoded is not None:
            line["payload"] = p.decoded
        self._append(line)
        c = self._census.setdefault(p.from_id, {"id": p.from_id, "first_heard": now,
                                                "last_heard": now, "packets": 0,
                                                "rssi": p.rssi, "snr": p.snr})
        c["last_heard"] = now
        c["packets"] += 1
        c["rssi"], c["snr"] = p.rssi, p.snr
        cs = self._chan.setdefault(p.channel, {"packets": 0, "decrypted": 0})
        cs["packets"] += 1
        cs["decrypted"] += 1 if decrypted else 0

    def census(self) -> list[dict]:
        return list(self._census.values())

    def channel_stats(self) -> dict[int, dict]:
        return dict(self._chan)

    def _append(self, obj: dict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")
```

- [ ] **Step 4: run — PASS. Step 5: commit** `feat(meshtastic): passive capture pipeline`.

---

### Task 7: Bridge — host-side serial↔MQTT

**Files:** Create `api/bridge.py`, `tests/test_bridge.py`.

**Interfaces:**
- Consumes: `gridpolicy.targets_for`, `config.Config`, `model.Packet`.
- Produces: `bridge.Bridge(cfg:Config, mqtt_factory:Callable[[str], MqttClient])` with `.publish(channel_name:str, p:Packet)` (publishes to shared/on brokers per policy), `.start()/.stop()`. `MqttClient` protocol: `.connect(host,port)`, `.publish(topic, payload)`, `.disconnect()`. Real impl wraps `paho.mqtt.client`; **tests inject a `FakeMqtt`** recording `(topic, payload)`.

- [ ] **Step 1: failing `tests/test_bridge.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from api.config import Config, ChannelCfg, BrokerCfg
from api.model import Packet

class FakeMqtt:
    def __init__(self): self.pub=[]; self.conn=None
    def connect(self, host, port): self.conn=(host,port)
    def publish(self, topic, payload): self.pub.append((topic, payload))
    def disconnect(self): pass

def _cfg(grid, on=False):
    return Config(region="EU_868", channels=[ChannelCfg("fam", tuple(grid), "psk")],
                  shared_grid=BrokerCfg("10.10.0.1:1883"),
                  on_grid=BrokerCfg("mqtt.x.org:8883", on))

def _p(): return Packet("!1","!ffffffff",0,"TEXT_MESSAGE_APP",{"text":"hi"},-90,5.0,3,1.0)

def test_shared_channel_publishes_to_private_broker_only():
    from api.bridge import Bridge
    made={}
    def fac(key): made[key]=FakeMqtt(); return made[key]
    b=Bridge(_cfg(["off","shared"]), fac); b.start(); b.publish("fam", _p())
    assert made["shared"].conn==("10.10.0.1",1883)
    assert "on" not in made and len(made["shared"].pub)==1
    topic,_=made["shared"].pub[0]; assert topic.startswith("msh/EU_868/2/e/fam/")

def test_offgrid_channel_publishes_nowhere():
    from api.bridge import Bridge
    made={}
    b=Bridge(_cfg(["off"]), lambda k: made.setdefault(k, FakeMqtt())); b.start(); b.publish("fam", _p())
    assert all(not m.pub for m in made.values())

def test_on_channel_publishes_only_when_enabled():
    from api.bridge import Bridge
    made={}
    b=Bridge(_cfg(["off","on"], on=True), lambda k: made.setdefault(k, FakeMqtt())); b.start(); b.publish("fam", _p())
    assert "on" in made and made["on"].conn==("mqtt.x.org",8883)
```

- [ ] **Step 2: run — FAIL. Step 3: implement `api/bridge.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — host-side serial↔MQTT bridge (grid-policy driven)."""
from __future__ import annotations
import json
from typing import Callable
from .config import Config
from .gridpolicy import targets_for
from .model import Packet


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
            cli = self._factory(tgt)
            cli.connect(host, int(port or "1883"))
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
```

- [ ] **Step 4: run — PASS. Step 5: commit** `feat(meshtastic): host-side MQTT bridge`.

---

### Task 8: Daemon — wire radio + cache + passive + bridge; control socket

**Files:** Create `api/daemon.py`, `sbin/secubox-meshtasticd`, `tests/test_daemon.py`.

**Interfaces:**
- Consumes: everything above.
- Produces: `daemon.Engine(cfg, radio, cache, capture, bridge, clock=time.time)` with `.on_receive(pkt_dict)` (parse → state.apply → cache.update → passive.record if mode≠active-only → bridge.publish for the packet's channel), `.snapshot() -> dict` (radio status + state + census + channel_stats + grids). `.decrypted_for(channel:int) -> bool` (True when a PSK secret is configured for that channel index). Daemon `main()` builds the real objects; **tests drive `Engine` with `MockRadio` + fakes.**

- [ ] **Step 1: failing `tests/test_daemon.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from api.config import Config, ChannelCfg, BrokerCfg
from api.cache import StateCache
from api.passive import PassiveCapture
from api.radio import MockRadio

class FakeMqtt:
    def __init__(self): self.pub=[]
    def connect(self,h,p): pass
    def publish(self,t,pl): self.pub.append((t,pl))
    def disconnect(self): pass

def _engine(tmp_path, grid=("off","shared"), mode="both"):
    from api.bridge import Bridge
    from api.daemon import Engine
    cfg = Config(mode=mode, region="EU_868", channels=[ChannelCfg("fam", grid, "fam-psk")],
                 shared_grid=BrokerCfg("10.10.0.1:1883"))
    made={}
    br = Bridge(cfg, lambda k: made.setdefault(k, FakeMqtt())); br.start()
    cap = PassiveCapture(tmp_path/"p.jsonl")
    eng = Engine(cfg, MockRadio(), StateCache(tmp_path/"s.json"), cap, br, clock=lambda:42.0)
    return eng, cap, made

def test_on_receive_updates_cache_and_bridges(tmp_path):
    eng, cap, made = _engine(tmp_path)
    eng.on_receive({"from":0x1,"to":0xffffffff,"channel":0,
                    "decoded":{"portnum":"TEXT_MESSAGE_APP","text":"hi"}})
    snap = eng.snapshot()
    assert snap["nodes"][0]["id"] == "!00000001"
    assert made["shared"].pub                       # bridged to private broker
    assert cap.census()                             # passive recorded (mode both)

def test_active_only_mode_skips_passive(tmp_path):
    eng, cap, made = _engine(tmp_path, mode="active-node")
    eng.on_receive({"from":0x1,"channel":0,"decoded":{"portnum":"NODEINFO_APP"}})
    assert cap.census() == []

def test_snapshot_reports_radio_present(tmp_path):
    eng,_,_ = _engine(tmp_path)
    assert eng.snapshot()["radio"] == "present"
```

- [ ] **Step 2: run — FAIL. Step 3: implement `api/daemon.py`** (Engine class per interface; `main()` builds real objects, opens serial → `radio: absent` when `None`, subscribes `radio.on("receive", self.on_receive)`, starts cache refresh; serves a uvicorn UDS app from `web.py`). Include `decrypted_for` = `any(c index has psk_secret)` heuristic: a channel is "decrypted" when a `ChannelCfg` exists at that index with a non-empty `psk_secret`.

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — daemon engine (wires radio/cache/passive/bridge)."""
from __future__ import annotations
import time
from .model import MeshState, parse_packet
from .gridpolicy import nft_egress_rules  # noqa: F401  (used by ctl; re-export locus)


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
```

- [ ] **Step 4: run — PASS. Step 5:** write `sbin/secubox-meshtasticd` (`#!/usr/bin/env bash` … `exec /usr/bin/python3 -m api.daemon "$@"`, `cd /usr/lib/secubox/meshtastic`). **Step 6: commit** `feat(meshtastic): daemon engine + launcher`.

---

### Task 9: ctl — privileged config (webui→ctl)

**Files:** Create `api/ctl.py`, `sbin/secubox-meshtasticctl`, `sudoers.d/secubox-meshtastic`, `tests/test_ctl.py`.

**Interfaces:**
- Produces: CLI `secubox-meshtasticctl` (root) verbs: `set-region <EU_868>`, `set-role <CLIENT_MUTE|…>`, `set-psk <channel> --secret <name>`, `set-grid <channel> --grid off,shared`, `apply-egress` (writes nft drop-in from `gridpolicy.nft_egress_rules`), `set-mode <mode>`. Each edits `/etc/secubox/meshtastic.toml` (line/section-preserving), audits to `/var/log/secubox/audit.log`, requires root. Test with `--root <tmp>` isolation (like profiles ctl) and `_running_as_root` monkeypatch.

- [ ] **Step 1–4: TDD** `set-grid` edits the channel's grid list + reloads config validates; `apply-egress` with no enabled on-grid writes an **empty** allow drop-in (DEFAULT DROP preserved); `set-mode turbo` → refused (argparse `choices`). Root guard returns 1 when not root. Egress paths derive from `--root` (real `/etc/secubox/nftables.d/…` only when `root==/etc/secubox`).

- [ ] **Step 5: implement `api/ctl.py`** (argparse verbs; TOML edit via a small section-aware writer or `tomlkit` if available else regenerate from parsed+modified structure; write nft drop-in via atomic write; audit append). Sudoers: scoped exact-command grants for each verb, `systemd-run`-wrapped (panel runs as `secubox` → sudo → ctl), same posture as `sudoers.d/secubox-profiles`.

- [ ] **Step 6: commit** `feat(meshtastic): secubox-meshtasticctl + sudoers`.

---

### Task 10: FastAPI webui backend

**Files:** Create `api/web.py`, `tests/test_web.py`.

**Interfaces:**
- Consumes: `StateCache`, JWT dep from `secubox_core.auth` (`require_jwt`), the daemon control socket for actions.
- Produces: `web.create_app(cache, send_cb, ctl_cb)` → FastAPI. Routes (all `Depends(require_jwt)`): `GET /api/v1/meshtastic/status` (cache), `GET /nodes`, `GET /messages`, `GET /packets` (passive feed), `POST /send {channel,text}` (→ `send_cb`), `POST /mode {mode}` / `POST /channel {name,grid,...}` / `POST /grid {channel,grid}` (→ `ctl_cb`, enum-validated, 422 on bad). Mirror the profiles `web.py` validate-before-delegate pattern.

- [ ] **Step 1–4: TDD** status returns cache dict; `POST /send` calls `send_cb`; `POST /mode` bad value → 422 and `ctl_cb` not called; unknown route/JWT missing → 401. Use FastAPI `TestClient`, inject fakes.

- [ ] **Step 5: implement `api/web.py`. Step 6: commit** `feat(meshtastic): FastAPI webui backend`.

---

### Task 11: webui panel (frontend)

**Files:** Create `www/meshtastic/index.html`.

- [ ] **Step 1:** Build the panel (cyan hybrid-dark skin, Courier Prime, emoji — WEBUI-PANEL-GUIDELINES). Tabs: **Nodes** (list + **offline canvas map**: plot `pos` lat/long normalized to the canvas, ring by SNR — no external tiles), **Messages** (per-channel send/receive; POST `/send`), **Channels** (per-channel grid toggle off/shared/on → POST `/grid`), **Sniffer** (packet feed from `/packets`, census table, channel-activity bars), **Grid** (radio present?, bridges up, mode selector → POST `/mode`). Reads `localStorage.sbx_token` for auth (the standard webui token key). Graceful `radio: absent` banner.
- [ ] **Step 2:** `node --check` the inline `<script>` (extract + validate, as done for the profiles panel).
- [ ] **Step 3: commit** `feat(meshtastic): webui panel`.

---

### Task 12: systemd + nginx + menu + private broker wiring

**Files:** Create `systemd/secubox-meshtasticd.service`, `debian/secubox-meshtasticd.service` (copy), `nginx/meshtastic.conf`, `menu.d/71-meshtastic.json`, mosquitto drop-in `conf/mosquitto-secubox-meshtastic.conf`.

- [ ] **Step 1:** `secubox-meshtasticd.service`: `User=secubox-meshtastic`, `SupplementaryGroups=dialout`, `ExecStart=/usr/sbin/secubox-meshtasticd`, hardened (`ProtectSystem=strict`, `ReadWritePaths=/run/secubox /var/cache/secubox/meshtastic /var/log/secubox/meshtastic`, `DeviceAllow=char-ttyUSB rw` + `char-ttyACM rw`), `RuntimeDirectory` **NOT** `=secubox` (avoid the shared-dir re-chown landmine — use `RuntimeDirectory=secubox-meshtastic` or none; it connects to `/run/secubox/*.sock` as client only). `Restart=on-failure`.
- [ ] **Step 2:** `nginx/meshtastic.conf`: `location /meshtastic/ { alias …www/meshtastic/; }` + `location /api/v1/meshtastic/ { proxy_pass http://unix:/run/secubox/meshtastic.sock; }` (preserve prefix — like profiles). `menu.d/71-meshtastic.json`: panel entry (📡 icon). Mosquitto drop-in binds `listener 1883 10.10.0.1` (MirrorNet IP) + `allow_anonymous false` + ACL.
- [ ] **Step 3: commit** `feat(meshtastic): systemd + nginx + menu + private broker`.

---

### Task 13: Debian packaging finalize + docs

**Files:** Modify `debian/{control,rules,install,postinst,prerm,changelog}`, create `README.md`.

- [ ] **Step 1:** `debian/install`: `api/*.py → usr/lib/secubox/meshtastic/api/`, `sbin/* → usr/sbin/`, `www/meshtastic/* → usr/share/secubox/www/meshtastic/`, `nginx/meshtastic.conf → etc/nginx/secubox-routes.d/`, `menu.d/* → usr/share/secubox/menu.d/`, `conf/meshtastic.toml.example → usr/share/secubox/meshtastic/`, `sudoers.d/secubox-meshtastic → etc/sudoers.d/` (0440), mosquitto drop-in.
- [ ] **Step 2:** `debian/postinst`: create `secubox-meshtastic` user (in `dialout`), dirs (`/etc/secubox/secrets/meshtastic` 0700, `/var/cache/secubox/meshtastic`, `/var/log/secubox/meshtastic` owned `secubox-meshtastic`, **`/var/log/secubox` stays 0755** — traversal constraint), install default `meshtastic.toml` if absent, `dh_installsystemd --name=secubox-meshtasticd`, enable+start (it runs `radio: absent` fine), `systemctl reload nginx`. `debian/rules` `override_dh_installsystemd` installs the unit from `systemd/`. `debian/control` `Depends: python3, python3-paho-mqtt, secubox-core, mosquitto`; document `meshtastic` pip dependency in README (not in Debian repos — install via pip/venv at deploy; the module runs `radio: absent` without it and only needs it when a device is attached).
- [ ] **Step 3:** `README.md` (API table, TOML options, grids, passive mode, the pip `meshtastic` note, link to spec + #897). Run `python3 scripts/license-headers.py` to verify SPDX headers. Full suite: `cd packages/secubox-meshtastic && python -m pytest tests/ -q` (all green).
- [ ] **Step 4:** Build: `cd packages/secubox-meshtastic && dpkg-buildpackage -us -uc -b`. Expect a clean `secubox-meshtastic_0.1.0-1~bookworm1_all.deb`.
- [ ] **Step 5: commit** `feat(meshtastic): debian packaging + README (ref #897)`.

---

## Deferred (hardware-gated — #897)

Real-device bring-up is **not** in this plan (no radio yet): flashing/region-set on the purchased device, `/dev/tty*` passthrough validation, real EU868 RX/TX from the valley, live shared-grid federation between two SecuBox nodes, and a live public-MQTT egress test. These become a follow-up "board validation" issue once #897 hardware arrives. Everything above is fully testable against `MockRadio` + `FakeMqtt` with **zero hardware**.
