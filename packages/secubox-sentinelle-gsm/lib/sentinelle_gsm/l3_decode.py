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


# Protocol-discriminator values (3GPP TS 24.007 §11.2.3.1.1)
L3_PD_CC = 0x03           # Call Control
L3_PD_MM = 0x05           # Mobility Management
L3_PD_RR = 0x06           # Radio Resources

# Message-type values inside RR (TS 44.018 §10.5)
RR_MSG_SI3      = 0x1a
RR_MSG_SI4      = 0x1c
RR_MSG_SI6      = 0x1e
RR_MSG_PAGING_REQUEST_1 = 0x21
RR_MSG_PAGING_REQUEST_2 = 0x22
RR_MSG_PAGING_REQUEST_3 = 0x24
RR_MSG_PAGING_RESPONSE  = 0x27

# Message-type values inside MM (TS 24.008 §10.4)
MM_MSG_LU_ACCEPT       = 0x02
MM_MSG_LU_REJECT       = 0x04
MM_MSG_LU_REQUEST      = 0x08
MM_MSG_AUTH_REQUEST    = 0x12
MM_MSG_TMSI_REALLOC    = 0x1a
MM_MSG_IDENTITY_REQ    = 0x18
MM_MSG_IDENTITY_RSP    = 0x19


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
        # GSMTAP raw_l3 payload starts with a L2 framing byte that varies
        # per channel: BCCH/CCCH downlink prefixes the L3 message with an
        # L2 pseudo-length byte (TS 44.006 §3.4); SDCCH uplink starts with
        # a LAPDm header (typically 2-3 bytes). Rather than tracking that
        # per-channel here, walk the first 4 bytes looking for the
        # protocol discriminator byte (low nibble = PD per TS 24.007).
        # Once we land on PD=RR or PD=MM, the next byte is the msg type.
        pd, off = _find_l3_start(raw)
        if pd is None or off + 1 >= len(raw):
            return ParsedFrame()
        body = raw[off:]
        msg_type = body[1]
        if pd == L3_PD_RR:
            if msg_type == RR_MSG_SI3:
                return ParsedFrame(cell_info=self._parse_si3(body))
            if msg_type == RR_MSG_SI4:
                return ParsedFrame(cell_info=self._parse_si4(body))
            if msg_type == RR_MSG_SI6:
                return ParsedFrame(cell_info=self._parse_si6(body))
            if msg_type in (RR_MSG_PAGING_REQUEST_1,
                            RR_MSG_PAGING_REQUEST_2,
                            RR_MSG_PAGING_REQUEST_3,
                            RR_MSG_PAGING_RESPONSE):
                return ParsedFrame(paging=self._parse_paging(body, msg_type))
        elif pd == L3_PD_MM:
            # MM Identity Response (uplink): mobile delivers its IMSI/IMEI
            # in cleartext. Same mobile-identity TLV layout as paging.
            if msg_type == MM_MSG_IDENTITY_RSP:
                return ParsedFrame(paging=self._parse_paging(body, msg_type))
            # MM LU Request: mobile sends its CKSN + LAI + MS Classmark
            # + Mobile Identity. TMSI/IMSI lives in the mobile identity.
            if msg_type == MM_MSG_LU_REQUEST:
                return ParsedFrame(paging=self._parse_lu_request(body))
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

    # ── Paging / identity parsers (CCCH + SDCCH) ───────────────────────
    def _parse_paging(self, raw: bytes, msg_type: int) -> ParsedPagingRequest:
        out = ParsedPagingRequest(paging_type=msg_type)
        # Where the first Mobile Identity TLV starts after the 2-byte L3
        # header (PD + msg_type) varies by message:
        #   Paging Request (1/2/3, downlink CCCH):   page_mode + ch_needed (1 B)
        #   Paging Response (uplink SDCCH):          ciphering key seq + classmark (4 B)
        #   MM Identity Response (uplink SDCCH):     identity starts immediately
        if msg_type == MM_MSG_IDENTITY_RSP:
            ptr = 2
        elif msg_type == RR_MSG_PAGING_RESPONSE:
            ptr = 2 + 1 + 3   # cksn+spare(1) + Mobile Station Classmark 2(3)
        else:
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

    def _parse_lu_request(self, raw: bytes) -> ParsedPagingRequest:
        """LU REQUEST contains a Mobile Identity (TMSI or IMSI) after the
        fixed header. Reuses ParsedPagingRequest as the carrier so the
        downstream pipeline gets a uniform subscriber-event shape."""
        out = ParsedPagingRequest(paging_type=MM_MSG_LU_REQUEST)
        ptr = LU_REQUEST_MOBILE_ID_OFFSET
        if ptr >= len(raw):
            return out
        mid, _ = _try_extract_mobile_id(raw, ptr)
        if mid is not None:
            id_type, plaintext_bytes = mid
            if id_type in (MID_TYPE_IMSI, MID_TYPE_TMSI):
                hashed = self._anon.anonymize(plaintext_bytes.hex())
                out.identities.append(PagedIdentity(
                    id_type=id_type, subscriber_hash=hashed,
                ))
        return out


# ── private helpers ─────────────────────────────────────────────────────
def _find_l3_start(buf: bytes) -> Tuple[Optional[int], int]:
    """Scan the first 4 bytes for the protocol-discriminator byte.

    Returns (pd_value, offset) on hit, or (None, 0) on miss. The L3 body
    is buf[offset:] — first byte = PD, second byte = msg type. Leading
    bytes before the PD are L2 framing (pseudo-length on BCCH/CCCH or
    a short LAPDm header on SDCCH).

    We accept ONLY exact PD bytes with transaction identifier = 0:
      0x06 = RR (System Info, Paging, Channel Assignment)
      0x05 = MM (LU Request/Accept, Identity Req/Rsp, Auth)
    A nibble-based match is too loose: a pseudo-length byte like 0x25
    also has low nibble 5, but it's not an MM message — accepting it
    would derail the msg-type read.
    """
    LIMIT = min(len(buf), 4)
    for ofs in range(LIMIT):
        b = buf[ofs]
        if b in (L3_PD_RR, L3_PD_MM):
            if ofs + 1 < len(buf):
                return b, ofs
    return None, 0


# LU REQUEST layout after the 2-byte L3 header (PD + msg_type):
#   1 byte:  CKSN + LU type
#   5 bytes: LAI (MCC/MNC + LAC)
#   1 byte:  MS Classmark 1
#   then mobile identity TLV
LU_REQUEST_MOBILE_ID_OFFSET = 2 + 1 + 5 + 1


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
    # ITU-T E.212 assigns MCCs in the range 200-999; anything below is a
    # parser misalignment on a frame whose layout we don't match. Treat
    # MCC=000 as "no decode" rather than poisoning the DB with bogus
    # "0-0-0-CCCC" cell_id entries.
    if mcc < 200:
        return None, None
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
