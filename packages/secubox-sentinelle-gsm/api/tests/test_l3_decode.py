# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""Tests for sentinelle_gsm.l3_decode — BCCH SI + CCCH paging parsing.

Privacy invariant verified : public dataclasses NEVER carry plaintext
IMSI/TMSI bytes — only HMAC-truncated subscriber_hash strings.
"""

import pytest

from sentinelle_gsm.observer import Anonymizer
from sentinelle_gsm.l3_decode import (
    L3Decode,
    MID_TYPE_IMSI,
    MID_TYPE_TMSI,
    ParsedFrame,
    _decode_bcd_imsi,
    _decode_mcc_mnc,
)


# ─── BCD encoder helpers (inverse of the decoder; for building synthetic
#     L3 frames in tests). The decoder is the spec reference; if these
#     helpers disagree, fix THEM, not the decoder.
# ──────────────────────────────────────────────────────────────────────


def _encode_bcd_mcc_mnc(mcc: int, mnc: int, three_digit_mnc: bool = False) -> bytes:
    """3-byte MCC/MNC encoding per TS 24.008 §10.5.1.3.

    Layout (decoder POV) :
      byte 0 : low nibble = MCC digit 1, high nibble = MCC digit 2
      byte 1 : low nibble = MCC digit 3, high nibble = MNC digit 3 OR 0xF
      byte 2 : low nibble = MNC digit 1, high nibble = MNC digit 2
    """
    m1, m2, m3 = mcc // 100, (mcc // 10) % 10, mcc % 10
    if not three_digit_mnc and mnc < 100:
        n1, n2 = mnc // 10, mnc % 10
        return bytes([
            (m2 << 4) | m1,
            (0xF << 4) | m3,
            (n2 << 4) | n1,
        ])
    # Decoder names : d_mnc_3 = hundreds, d_mnc_2 = tens, d_mnc_1 = ones.
    hundreds, tens, ones = mnc // 100, (mnc // 10) % 10, mnc % 10
    return bytes([
        (m2 << 4) | m1,
        (hundreds << 4) | m3,
        (tens << 4) | ones,
    ])


def _encode_bcd_imsi_body(imsi: str) -> bytes:
    """Mobile Identity IMSI BCD per TS 24.008 §10.5.1.4.

    Layout (decoder POV) :
      body[0] : high nibble = first IMSI digit
                low  nibble = (odd<<3) | MID_TYPE_IMSI (= 0x01)
      body[k] (k>=1) : low nibble = digit 2k, high nibble = digit 2k+1
      For even-length IMSI, last high nibble = 0xF (filler).
    """
    odd = (len(imsi) % 2) == 1
    type_nibble = ((1 if odd else 0) << 3) | MID_TYPE_IMSI
    body = bytearray()
    body.append((int(imsi[0]) << 4) | type_nibble)
    i = 1
    while i < len(imsi):
        low = int(imsi[i])
        high = int(imsi[i + 1]) if (i + 1) < len(imsi) else 0xF
        body.append((high << 4) | low)
        i += 2
    return bytes(body)


def _encode_bcd_tmsi_body(tmsi_bytes: bytes) -> bytes:
    """Mobile Identity TMSI per TS 24.008 §10.5.1.4.

    Layout (decoder POV) :
      body[0] : type byte; low 3 bits = MID_TYPE_TMSI (= 4)
      body[1..5] : the 4-byte TMSI value
    """
    assert len(tmsi_bytes) == 4
    type_byte = 0xF0 | MID_TYPE_TMSI    # high nibble 0xF per spec, low = type
    return bytes([type_byte]) + tmsi_bytes


def _wrap_mobile_id(body: bytes) -> bytes:
    """TLV wrapper : 1-byte length + body."""
    return bytes([len(body)]) + body


# ─── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def decoder():
    return L3Decode(Anonymizer.ephemeral())


# ─── BCD helper tests (spec sanity checks) ────────────────────────────


def test_decode_mcc_mnc_2_digit_mnc():
    """Orange FR : MCC=208, MNC=01 — 2-digit MNC, 0xF filler nibble."""
    buf = _encode_bcd_mcc_mnc(208, 1)
    mcc, mnc = _decode_mcc_mnc(buf)
    assert mcc == 208
    assert mnc == 1


def test_decode_mcc_mnc_3_digit_mnc():
    """Verizon US : MCC=311, MNC=480 — 3-digit MNC, no filler."""
    buf = _encode_bcd_mcc_mnc(311, 480, three_digit_mnc=True)
    mcc, mnc = _decode_mcc_mnc(buf)
    assert mcc == 311
    assert mnc == 480


def test_decode_bcd_imsi_15_digits_odd():
    """IMSI 208201234567890 = 15 digits (odd → odd flag set)."""
    body = _encode_bcd_imsi_body("208201234567890")
    digits = _decode_bcd_imsi(body)
    assert digits == "208201234567890"


# ─── End-to-end L3 frame tests ────────────────────────────────────────


def test_parse_si3_extracts_mcc_mnc_lac_ci(decoder):
    """SI Type 3 (BCCH) yields a populated CellInfo."""
    raw = (
        b"\x06\x1a"                                  # L3 header (PD=RR, msg=SI3)
        + (12345).to_bytes(2, "big")                 # CI = 12345
        + _encode_bcd_mcc_mnc(208, 1)                # LAI: MCC=208, MNC=01
        + (200).to_bytes(2, "big")                   # LAC = 200
        + b"\x00\x00\x00"                            # control_channel_description
        + b"\x00"                                    # cell_options (no A5 bits)
        + b"\x00\x00"                                # cell_selection
        + b"\x00\x00\x00"                            # rach_control
    )
    frame = decoder.parse(raw)
    assert frame.cell_info is not None
    assert frame.paging is None
    assert frame.cell_info.mcc == 208
    assert frame.cell_info.mnc == 1
    assert frame.cell_info.lac == 200
    assert frame.cell_info.ci == 12345


def test_parse_si6_extracts_cipher(decoder):
    """SI Type 6 advertises the supported A5 algorithm in cell_options."""
    # cell_options byte : A5 field = bits 5..7 → 0b011 << 5 = 0x60 → A5/3
    cell_options = (0x03 << 5) & 0xFF
    raw = (
        b"\x06\x1e"                                  # L3 header (PD=RR, msg=SI6)
        + (42).to_bytes(2, "big")                    # CI
        + _encode_bcd_mcc_mnc(208, 1)                # LAI
        + (123).to_bytes(2, "big")                   # LAC
        + bytes([cell_options])                      # cipher byte
    )
    frame = decoder.parse(raw)
    assert frame.cell_info is not None
    assert frame.cell_info.a5_advertised == 3
    assert frame.cell_info.mcc == 208
    assert frame.cell_info.lac == 123


def test_parse_paging_request_1_with_tmsi(decoder):
    """Paging Request Type 1 with a single TMSI → HMAC hash, NOT plaintext."""
    tmsi = b"\xDE\xAD\xBE\xEF"
    mid_tlv = _wrap_mobile_id(_encode_bcd_tmsi_body(tmsi))
    raw = b"\x06\x21" + b"\x00" + mid_tlv     # L3 header + page_mode byte + MID
    frame = decoder.parse(raw)
    assert frame.paging is not None
    assert frame.cell_info is None
    assert len(frame.paging.identities) == 1
    pid = frame.paging.identities[0]
    assert pid.id_type == MID_TYPE_TMSI
    # Privacy invariant : hash is NOT the plaintext TMSI in any encoding
    assert pid.subscriber_hash != "deadbeef"
    assert pid.subscriber_hash != tmsi.hex()
    assert len(pid.subscriber_hash) == 16     # ANON_TRUNCATE_HEX


def test_parse_paging_request_with_imsi(decoder):
    """Paging Request with an IMSI identity → still hashed, never plaintext."""
    imsi = "208201234567890"
    mid_tlv = _wrap_mobile_id(_encode_bcd_imsi_body(imsi))
    raw = b"\x06\x21" + b"\x00" + mid_tlv
    frame = decoder.parse(raw)
    assert frame.paging is not None
    assert len(frame.paging.identities) == 1
    pid = frame.paging.identities[0]
    assert pid.id_type == MID_TYPE_IMSI
    # Privacy invariant : the plaintext IMSI never appears in the hash
    assert imsi not in pid.subscriber_hash
    assert len(pid.subscriber_hash) == 16


def test_unknown_msg_type_returns_empty_frame(decoder):
    frame = decoder.parse(b"\x06\xFF\x00\x00")
    assert frame.cell_info is None
    assert frame.paging is None


def test_truncated_input_returns_empty(decoder):
    """Permissive parsing : truncated / empty input must NOT raise."""
    empty = ParsedFrame()
    assert decoder.parse(b"") == empty
    assert decoder.parse(b"\x06") == empty
    # Wrong protocol discriminator
    assert decoder.parse(b"\x08\x1a\x00\x00") == empty
