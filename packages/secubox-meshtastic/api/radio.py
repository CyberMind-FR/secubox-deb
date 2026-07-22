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
