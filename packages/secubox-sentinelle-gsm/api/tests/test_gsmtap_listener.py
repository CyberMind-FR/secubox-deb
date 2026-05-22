# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import asyncio
import socket
import struct
import pytest
from sentinelle_gsm.gsmtap_listener import GsmtapListener, _parse_gsmtap_header


def _build_gsmtap_v2(arfcn: int = 124, frame_nr: int = 0xABCDEF,
                    channel: int = 0x01) -> bytes:
    """Minimal valid GSMTAP v2 16-byte header + empty payload."""
    return struct.pack(
        ">BBBBHbbIBBBB",
        0x02,                  # version
        4,                     # hdr_len/4
        0x01,                  # payload_type = Um
        0,                     # timeslot
        arfcn,                 # arfcn
        -85,                   # signal_dbm
        20,                    # snr_db
        frame_nr,              # frame_nr (u32 BE)
        channel,               # channel
        0,                     # antenna
        0,                     # sub_type
        0,                     # reserved
    )


def test_parse_header_minimum_valid():
    buf = _build_gsmtap_v2(arfcn=124, frame_nr=0x12345, channel=0x04)
    hdr = _parse_gsmtap_header(buf)
    assert hdr is not None
    assert hdr["arfcn"] == 124
    assert hdr["frame_nr"] == 0x12345
    assert hdr["channel"] == 0x04


def test_parse_header_rejects_too_short():
    assert _parse_gsmtap_header(b"\x02\x04\x01\x00") is None


def test_parse_header_rejects_wrong_version():
    buf = bytearray(_build_gsmtap_v2())
    buf[0] = 0x01      # wrong version
    assert _parse_gsmtap_header(bytes(buf)) is None


@pytest.mark.asyncio
async def test_listener_receives_a_datagram(tmp_path):
    # Use a high local port to avoid colliding with a running grgsm.
    listener = GsmtapListener(host="127.0.0.1", port=47291)
    await listener.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(_build_gsmtap_v2(arfcn=42, channel=0x04), ("127.0.0.1", 47291))

        async def first():
            async for obs in listener.observations():
                return obs
        obs = await asyncio.wait_for(first(), timeout=1.0)
        assert obs.arfcn == 42
        assert obs.channel == 0x04
    finally:
        await listener.stop()
