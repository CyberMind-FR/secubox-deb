# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — radio interface (real serial + test mock).

The real SerialRadio imports `meshtastic` LAZILY inside open_serial() so the
test suite (which uses MockRadio) never needs the library or a serial port."""
from __future__ import annotations
import gc
import os
import sys
import time
from typing import Callable, Protocol


class RadioInterface(Protocol):
    def on(self, event: str, cb: Callable) -> None: ...
    def send_text(self, text: str, channel: int = 0) -> None: ...
    def close(self) -> None: ...


class MockRadio:
    def __init__(self, node_db=None, my_num=None) -> None:
        self._cbs: dict[str, list[Callable]] = {}
        self.sent: list[tuple[str, int]] = []
        self._node_db = list(node_db or [])
        self._my_num = my_num

    def node_db(self) -> list[dict]:
        return list(self._node_db)

    def my_num(self):
        return self._my_num

    def on(self, event: str, cb: Callable) -> None:
        self._cbs.setdefault(event, []).append(cb)

    def emit(self, event: str, payload) -> None:
        for cb in self._cbs.get(event, []):
            cb(payload)

    def send_text(self, text: str, channel: int = 0) -> None:
        self.sent.append((text, channel))

    def close(self) -> None:
        pass


def _dbg(msg: str) -> None:
    # Diagnostics go to stderr (journald), NOT the logging module: importing
    # meshtastic reconfigures the root logger, which silently swallows
    # logging-module output from this path (a real "radio absent" was
    # invisible in the journal for exactly this reason).
    print(f"[meshtastic] {msg}", file=sys.stderr, flush=True)


def open_serial(dev: str, *, attempts: int = 3, delay: float = 2.0) -> RadioInterface | None:
    """Return a live radio, or None if the device is absent (radio: absent).

    The open is retried. On a service restart the previous instance may still
    be releasing the serial port (its SerialInterface background thread + the
    pyserial FD outlive the SIGTERM by a moment), so the first handshake can
    land on a locked or half-reset device. A SerialInterface() that raises
    mid-``__init__`` also LEAKS the pyserial FD it already opened (the object
    is dropped before we get a reference), which would keep the port locked for
    every later attempt — ``gc.collect()`` finalises that orphan so the retry
    can re-lock and re-handshake.
    """
    if dev != "auto" and not os.path.exists(dev):
        _dbg(f"radio path absent: {dev}")
        return None
    try:
        from meshtastic.serial_interface import SerialInterface  # lazy
        from pubsub import pub
    except Exception as e:  # library not installed / broken
        _dbg(f"meshtastic lib import failed: {e!r}")
        return None
    last: Exception | None = None
    for i in range(1, attempts + 1):
        try:
            iface = SerialInterface(devPath=None if dev == "auto" else dev)
            _dbg(f"radio opened on attempt {i} (dev={dev})")
            return _SerialRadio(iface, pub)
        except Exception as e:
            last = e
            _dbg(f"radio open attempt {i}/{attempts} failed: {e!r}")
            gc.collect()  # release the orphaned pyserial FD so the next attempt can lock the port
            if i < attempts:
                time.sleep(delay)
    _dbg(f"radio absent after {attempts} attempts: {last!r}")
    return None


class _SerialRadio:
    def __init__(self, iface, pub) -> None:
        self._iface, self._pub = iface, pub

    def on(self, event: str, cb: Callable) -> None:
        topic = {"receive": "meshtastic.receive",
                 "node": "meshtastic.node.updated",
                 "connection": "meshtastic.connection.established"}[event]
        if event == "receive":
            handler = lambda packet=None, interface=None, **kw: cb(packet or {})
        elif event == "node":
            handler = lambda node=None, interface=None, **kw: cb(node or {})
        else:  # "connection"
            handler = lambda interface=None, **kw: cb(interface or {})
        self._pub.subscribe(handler, topic)

    def send_text(self, text: str, channel: int = 0) -> None:
        self._iface.sendText(text, channelIndex=channel)

    def my_num(self):
        try:
            return self._iface.myInfo.my_node_num
        except Exception:
            return None

    def node_db(self) -> list[dict]:
        """Snapshot the device's node DB (self + every node it already knows).
        Lets the panel show the local node + known peers immediately on connect,
        instead of staying empty until fresh packets arrive."""
        out: list[dict] = []
        try:
            my = self.my_num()
            for val in (getattr(self._iface, "nodes", None) or {}).values():
                u = val.get("user") or {}
                num = val.get("num")
                out.append({
                    "num": num,
                    "user": {"shortName": u.get("shortName", ""),
                             "longName": u.get("longName", ""),
                             "role": u.get("role", "")},
                    "position": val.get("position") or {},
                    "deviceMetrics": val.get("deviceMetrics") or {},
                    "snr": val.get("snr"),
                    "is_self": num is not None and num == my,
                })
        except Exception:
            pass
        return out

    def close(self) -> None:
        try: self._iface.close()
        except Exception: pass
