# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
L3 decoder tests against real GSMTAP-captured hex samples (v0.4.0).

The samples below were captured live on gk2 against an Orange France
2G cell on ARFCN 9 / 936.8 MHz, then trimmed to just the L3 payload
(content of GSMTAP UDP datagram after the 16-byte GSMTAP header).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from sentinelle_gsm.l3_decode import (
    L3Decode,
    L3_PD_MM,
    L3_PD_RR,
    MID_TYPE_TMSI,
    RR_MSG_PAGING_RESPONSE,
    _find_l3_start,
)
from sentinelle_gsm.observer import Anonymizer, Mode


@pytest.fixture
def l3():
    return L3Decode(Anonymizer.ephemeral(mode=Mode.PROD))


def test_find_l3_start_skips_pseudo_length():
    # SI4 capture: pseudo-length 0x31, then PD 0x06, msg 0x1c, LAI…
    buf = bytes.fromhex("3106 1c02f810 2901 4500".replace(" ", ""))
    pd, ofs = _find_l3_start(buf)
    assert pd == L3_PD_RR
    assert ofs == 1


def test_find_l3_start_direct_pd():
    # No prefix, PD at 0
    buf = bytes.fromhex("06 1c 02f810 2901".replace(" ", ""))
    pd, ofs = _find_l3_start(buf)
    assert pd == L3_PD_RR
    assert ofs == 0


def test_find_l3_start_mm_pd():
    # LAPDm-prefixed MM Identity Response
    buf = bytes.fromhex("0301 1f 05 19 0830000102030405".replace(" ", ""))
    pd, ofs = _find_l3_start(buf)
    assert pd == L3_PD_MM
    assert ofs == 3


def test_find_l3_start_no_pd():
    # All filler — should return None
    assert _find_l3_start(b"\x2b\x2b\x2b\x2b") == (None, 0)


def test_parse_si4_real_orange_france_hex(l3):
    """Captured SI4 from Orange France 2G cell on 936.8 MHz.

    Expected decoded LAI: MCC=208 (FR), MNC=01 (Orange), LAC=0x2901."""
    # pseudo_len(0x31) PD(0x06) msg(0x1c=SI4) LAI(02f810) LAC(2901) CI(4500) + padding
    raw = bytes.fromhex("3106 1c 02f810 2901 4500 5c00 0080 0043"
                        + "2b" * 8)
    parsed = l3.parse(raw)
    assert parsed.cell_info is not None
    ci = parsed.cell_info
    assert ci.mcc == 208
    assert ci.mnc == 1
    assert ci.lac == 0x2901


def test_parse_paging_response_extracts_tmsi(l3):
    """Captured Paging Response uplink on SDCCH carrying a 4-byte TMSI.

    Frame: pseudo_len(0x25) PD(0x06) msg(0x27=Paging Response)
           cksn+spare(0x00) classmark2(05f4c0)  ← actually 3 bytes
           identity: L=5 type=0xf4(TMSI) tmsi=c0e80a32  ← real captured TMSI
    """
    # Build the frame with proper structure: 0x25 06 27 then 1+3 bytes
    # then identity TLV `05 f4 c0 e8 0a 32`
    raw = bytes.fromhex("25 06 27 00 050505 05f4c0e80a32 2b 2b".replace(" ", ""))
    parsed = l3.parse(raw)
    assert parsed.paging is not None
    assert parsed.paging.paging_type == RR_MSG_PAGING_RESPONSE
    # One TMSI identity extracted, hashed (not plaintext)
    assert len(parsed.paging.identities) == 1
    pid = parsed.paging.identities[0]
    assert pid.id_type == MID_TYPE_TMSI
    # Hash must NOT contain plaintext bytes; must be hex
    assert all(c in "0123456789abcdef" for c in pid.subscriber_hash)
    assert "c0e80a32" not in pid.subscriber_hash


def test_parse_returns_empty_on_filler(l3):
    parsed = l3.parse(b"\x2b" * 22)
    assert parsed.cell_info is None
    assert parsed.paging is None


def test_parse_returns_empty_on_short_buffer(l3):
    parsed = l3.parse(b"")
    assert parsed.cell_info is None
    assert parsed.paging is None
    parsed = l3.parse(b"\x06")
    assert parsed.cell_info is None
    assert parsed.paging is None
