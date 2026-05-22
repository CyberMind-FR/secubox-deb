# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Async UDP listener for GSMTAP frames emitted by grgsm_livemon_headless.

Yields typed Observation events upstream. Privacy: any IMSI/TMSI
detected in the parsed L3 payload is HMAC-hashed via Anonymizer
BEFORE being placed in the Observation; no plaintext subscriber ID
ever crosses this module's API surface.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from typing import AsyncIterator, Optional


GSMTAP_TYPE_UM   = 0x01   # GSM Um frame
GSMTAP_TYPE_ABIS = 0x02
GSMTAP_CHANNEL_BCCH = 0x01
GSMTAP_CHANNEL_CCCH = 0x04


@dataclasses.dataclass
class Observation:
    ts: float
    arfcn: int
    frame_nr: int
    channel: int           # GSMTAP channel type
    sub_type: int          # GSMTAP sub_type
    raw_l3: bytes = b""    # L3 payload after GSMTAP header (BCCH SI / CCCH paging)
    lac: Optional[int] = None
    ci:  Optional[int]  = None
    mcc: Optional[int]  = None
    mnc: Optional[int]  = None
    cell_id: Optional[str] = None   # canonical "MCC-MNC-LAC-CI"
    subscriber_hash: Optional[str] = None   # HMAC-trunc, NEVER plaintext


def _parse_gsmtap_header(buf: bytes) -> Optional[dict]:
    """Tiny manual GSMTAP v2 header parser (16 bytes fixed).

    Saves us a runtime scapy dep for the hot path; we only use scapy
    for the deep L3 decode (BCCH info, paging requests) where it
    actually carries its weight.
    """
    if len(buf) < 16 or buf[0] != 0x02:           # version 2
        return None
    hdr_len_x4 = buf[1] * 4
    if hdr_len_x4 < 16:
        return None
    return {
        "version":   buf[0],
        "hdr_len":   hdr_len_x4,
        "payload_type": buf[2],
        "timeslot":  buf[3],
        "arfcn":     ((buf[4] & 0x3F) << 8) | buf[5],
        "signal_dbm": buf[6] - 256 if buf[6] > 127 else buf[6],
        "snr_db":    buf[7] - 256 if buf[7] > 127 else buf[7],
        "frame_nr":  int.from_bytes(buf[8:12], "big"),
        "channel":   buf[12],
        "antenna":   buf[13],
        "sub_type":  buf[14],
    }


class GsmtapListener:
    def __init__(self, host: str = "127.0.0.1", port: int = 4729):
        self.host = host
        self.port = port
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._queue: asyncio.Queue[Observation] = asyncio.Queue(maxsize=2048)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _GsmtapProtocol(self._on_datagram),
            local_addr=(self.host, self.port),
            reuse_port=False,
        )

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def _on_datagram(self, data: bytes) -> None:
        hdr = _parse_gsmtap_header(data)
        if hdr is None:
            return
        raw_l3 = data[hdr["hdr_len"]:]
        obs = Observation(
            ts=time.time(),
            arfcn=hdr["arfcn"],
            frame_nr=hdr["frame_nr"],
            channel=hdr["channel"],
            sub_type=hdr["sub_type"],
            raw_l3=raw_l3,
        )
        # L3 payload is now exposed via Observation.raw_l3 for v0.3.1
        # downstream decoders (BCCH System Information, CCCH paging).
        # Header-only metadata is still populated for legacy consumers.
        try:
            self._queue.put_nowait(obs)
        except asyncio.QueueFull:
            pass    # drop on overflow; observations are stochastic anyway

    async def observations(self) -> AsyncIterator[Observation]:
        while True:
            yield await self._queue.get()


class _GsmtapProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback):
        self._callback = callback

    def datagram_received(self, data: bytes, addr) -> None:
        self._callback(data)
