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
