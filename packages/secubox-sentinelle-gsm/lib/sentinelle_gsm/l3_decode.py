# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
GSM L3 message decoder — minimal subset for IMSI-catcher detection.

Hard invariant : public API NEVER emits plaintext IMSI/TMSI/IMEI.
The internal `_try_extract_mobile_id()` returns plaintext bytes; the
public `_parse_paging()` immediately calls Anonymizer.anonymize() on
those bytes BEFORE building the ParsedPagingRequest dataclass. The
plaintext goes out of scope at function return.

Reference :
  3GPP TS 24.008 §10.5.1.3  Location Area Identification (LAI / MCC+MNC)
  3GPP TS 24.008 §10.5.1.4  Mobile Identity (IMSI, TMSI, IMEI encoding)
  3GPP TS 44.018 §9.1       BCCH / CCCH message structures
"""

from __future__ import annotations

import dataclasses
from typing import List, Optional, Tuple

from sentinelle_gsm.observer import Anonymizer


# Pseudo-length / protocol-discriminator masks
L3_PD_RR = 0x06           # Radio Resources protocol discriminator

# Message-type values inside RR
RR_MSG_SI3      = 0x1a
RR_MSG_SI4      = 0x1c
RR_MSG_SI6      = 0x1e
RR_MSG_PAGING_REQUEST_1 = 0x21
RR_MSG_PAGING_REQUEST_2 = 0x22
RR_MSG_PAGING_REQUEST_3 = 0x24


# Mobile Identity type tags (TS 24.008 §10.5.1.4)
MID_TYPE_NONE = 0
MID_TYPE_IMSI = 1
MID_TYPE_IMEI = 2
MID_TYPE_IMEISV = 3
MID_TYPE_TMSI = 4


@dataclasses.dataclass
class CellInfo:
    """SI3/SI4/SI6-derived cell metadata. NO subscriber-id fields."""
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    lac: Optional[int] = None
    ci:  Optional[int] = None
    a5_advertised: Optional[int] = None    # 0=A5/0, 1=A5/1, 3=A5/3 etc.
    t3212_minutes: Optional[int] = None


@dataclasses.dataclass
class PagedIdentity:
    """ONE paged subscriber. subscriber_hash is HMAC-trunc, never plaintext."""
    id_type: int                    # MID_TYPE_TMSI or MID_TYPE_IMSI
    subscriber_hash: str            # HMAC-trunc via Anonymizer


@dataclasses.dataclass
class ParsedPagingRequest:
    paging_type: int                # RR_MSG_PAGING_REQUEST_{1,2,3}
    identities: List[PagedIdentity] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ParsedFrame:
    """Result of L3Decode.parse() — at most one of these is populated."""
    cell_info: Optional[CellInfo] = None
    paging:    Optional[ParsedPagingRequest] = None


class L3Decode:
    def __init__(self, anonymizer: Anonymizer):
        self._anon = anonymizer

    def parse(self, raw: bytes) -> ParsedFrame:
        if len(raw) < 2 or raw[0] != L3_PD_RR:
            return ParsedFrame()
        msg_type = raw[1]
        if msg_type == RR_MSG_SI3:
            return ParsedFrame(cell_info=self._parse_si3(raw))
        if msg_type == RR_MSG_SI4:
            return ParsedFrame(cell_info=self._parse_si4(raw))
        if msg_type == RR_MSG_SI6:
            return ParsedFrame(cell_info=self._parse_si6(raw))
        if msg_type in (RR_MSG_PAGING_REQUEST_1,
                        RR_MSG_PAGING_REQUEST_2,
                        RR_MSG_PAGING_REQUEST_3):
            return ParsedFrame(paging=self._parse_paging(raw, msg_type))
        return ParsedFrame()

    # ── SI parsers (BCCH) ──────────────────────────────────────────────
    def _parse_si3(self, raw: bytes) -> CellInfo:
        # TS 44.018 §9.1.35 — System Information Type 3
        # Offsets after the 2-byte L3 header:
        #   ci          (2 bytes)
        #   lai         (5 bytes  = mcc/mnc/lac)
        #   control_channel_description (3 bytes)
        #   cell_options_bcch (1 byte; bits 0-2 = supported encryption alg mask)
        #   cell_selection_params (2 bytes)
        #   rach_control_params (3 bytes)
        if len(raw) < 16:
            return CellInfo()
        ci = int.from_bytes(raw[2:4], "big")
        mcc, mnc = _decode_mcc_mnc(raw[4:7])
        lac = int.from_bytes(raw[7:9], "big")
        cell_options = raw[12]
        # Bits 0-2 = NCC permitted (not encryption); the actual A5 mask
        # is in the upper nibble of byte 12 in some variants — we read
        # both candidates and prefer the higher A5.
        a5 = _decode_a5_from_cell_options(cell_options)
        # T3212 timeout (in deci-hours, 1 byte) is in cell_selection_params
        t3212_min = raw[13] * 6 if len(raw) > 13 else None     # rough
        return CellInfo(mcc=mcc, mnc=mnc, lac=lac, ci=ci,
                        a5_advertised=a5, t3212_minutes=t3212_min)

    def _parse_si4(self, raw: bytes) -> CellInfo:
        # TS 44.018 §9.1.36 — Type 4 carries LAI + Cell Identity
        if len(raw) < 9:
            return CellInfo()
        mcc, mnc = _decode_mcc_mnc(raw[2:5])
        lac = int.from_bytes(raw[5:7], "big")
        return CellInfo(mcc=mcc, mnc=mnc, lac=lac)

    def _parse_si6(self, raw: bytes) -> CellInfo:
        # TS 44.018 §9.1.40 — Type 6 carries Cell Identity + LAI +
        # cell_options bytes with A5 advertised algorithms
        if len(raw) < 10:
            return CellInfo()
        ci = int.from_bytes(raw[2:4], "big")
        mcc, mnc = _decode_mcc_mnc(raw[4:7])
        lac = int.from_bytes(raw[7:9], "big")
        a5 = _decode_a5_from_cell_options(raw[9]) if len(raw) > 9 else None
        return CellInfo(mcc=mcc, mnc=mnc, lac=lac, ci=ci, a5_advertised=a5)

    # ── Paging parsers (CCCH) ──────────────────────────────────────────
    def _parse_paging(self, raw: bytes, msg_type: int) -> ParsedPagingRequest:
        out = ParsedPagingRequest(paging_type=msg_type)
        # After the 2-byte L3 header :
        #   page_mode + channel_needed (1 byte for type 1; differs slightly per variant)
        #   then 1-N mobile identities
        ptr = 3
        while ptr < len(raw):
            mid, consumed = _try_extract_mobile_id(raw, ptr)
            if mid is None or consumed == 0:
                break
            ptr += consumed
            id_type, plaintext_bytes = mid
            if id_type in (MID_TYPE_IMSI, MID_TYPE_TMSI):
                hashed = self._anon.anonymize(plaintext_bytes.hex())
                out.identities.append(PagedIdentity(
                    id_type=id_type, subscriber_hash=hashed,
                ))
            # plaintext_bytes goes out of scope here
        return out


# ── private helpers ─────────────────────────────────────────────────────
def _decode_mcc_mnc(buf: bytes) -> Tuple[Optional[int], Optional[int]]:
    """3-byte BCD MCC/MNC encoding per TS 24.008 §10.5.1.3."""
    if len(buf) < 3:
        return None, None
    d1 = buf[0] & 0x0F
    d2 = (buf[0] >> 4) & 0x0F
    d3 = buf[1] & 0x0F
    d_mnc_3 = (buf[1] >> 4) & 0x0F      # 0x0F means 2-digit MNC
    d_mnc_1 = buf[2] & 0x0F
    d_mnc_2 = (buf[2] >> 4) & 0x0F
    if 0xF in (d1, d2, d3) or d1 > 9 or d2 > 9 or d3 > 9:
        return None, None
    mcc = d1 * 100 + d2 * 10 + d3
    if d_mnc_3 == 0xF:
        mnc = d_mnc_1 * 10 + d_mnc_2
    else:
        mnc = d_mnc_3 * 100 + d_mnc_2 * 10 + d_mnc_1
    return mcc, mnc


def _decode_a5_from_cell_options(byte: int) -> Optional[int]:
    """The A5 advertised algorithm is encoded in the high bits of the
    cell_options byte in SI3/SI6. Map back to A5/X integer (0..7)."""
    # cell_options[5:7] = 3 bits encoding A5/1..A5/7 ; spec says 0 = A5/1
    a5_field = (byte >> 5) & 0x07
    return a5_field


def _try_extract_mobile_id(buf: bytes, ofs: int) -> Tuple[Optional[Tuple[int, bytes]], int]:
    """Return ((id_type, plaintext_bytes), bytes_consumed) or (None, 0).

    TS 24.008 §10.5.1.4 — Mobile Identity TLV :
      byte 0 = length L
      byte 1+ = identity (L bytes); low nibble of byte 1 = type+odd/even
    """
    if ofs >= len(buf):
        return None, 0
    L = buf[ofs]
    if L == 0 or ofs + 1 + L > len(buf):
        return None, 0
    body = buf[ofs + 1 : ofs + 1 + L]
    if not body:
        return None, 0
    id_type = body[0] & 0x07
    if id_type == MID_TYPE_TMSI:
        # TMSI = 4 bytes
        if L < 5:
            return None, 0
        return (id_type, bytes(body[1:5])), 1 + L
    if id_type == MID_TYPE_IMSI:
        # IMSI BCD = up to 15 digits
        digits = _decode_bcd_imsi(body)
        if not digits:
            return None, 0
        return (id_type, digits.encode("ascii")), 1 + L
    return None, 1 + L


def _decode_bcd_imsi(body: bytes) -> str:
    """Body byte 0 high-nibble = first IMSI digit ; odd flag in body byte 0 low-nibble."""
    if not body:
        return ""
    odd = bool(body[0] & 0x08)
    digits = [(body[0] >> 4) & 0x0F]
    for b in body[1:]:
        digits.append(b & 0x0F)
        digits.append((b >> 4) & 0x0F)
    if not odd and digits and digits[-1] == 0x0F:
        digits.pop()
    if any(d > 9 for d in digits):
        return ""
    return "".join(str(d) for d in digits)
