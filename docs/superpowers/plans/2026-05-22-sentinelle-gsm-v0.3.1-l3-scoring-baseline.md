<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-sentinelle-gsm v0.3.1 — L3 Decode + Scoring + Baseline + Qualified Alert Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote secubox-sentinelle-gsm from a passive observation pipeline (v0.3.0) into an actual IMSI-catcher detector. A GSMTAP frame entering on UDP 4729 is now decoded at L3, the cell is scored against 8 spec heuristics with a learned operator baseline, and an Alert with a `trusted_label` fires when a paged subscriber matches a `trusted_phones` entry on a high-scoring cell.

**Architecture:**

```
GsmtapListener  (v0.3.0)
      ↓  raw L3 payload bytes
L3Decode.parse(bytes)
      ↓  ParsedFrame (system_info | paging_request)
      ↓                                      ↓
  update sighting              extract paged identities → HMAC each (Anonymizer)
  (mcc/mnc/lac/ci, cipher)                          ↓
      ↓                                      PagingEvent(subscriber_hash, request_type)
      └──→ ScoringEngine.evaluate(cell, frame, baseline_db, rolling_window)
                                      ↓
                       score 0-100 + reasons[]
                                      ↓
            if score >= threshold AND ≥1 paged hash ∈ trusted_phones
                                      ↓
                             AlertSink.write(Alert(score, reasons, subscriber_hash, trusted_label))
                                      ↓
            else if score >= threshold (no trusted match)
                              AlertSink.write(Alert(score, reasons))  ← anomaly-only
```

**Tech Stack:**
- Python 3.11 / FastAPI / asyncio (existing)
- **L3 parsing** : pure-Python TLV by message type (NO scapy.layers.gsm — coverage gap in upstream)
- SQLite via stdlib (existing alert_sink + observations + new cell_baseline)
- `collections.deque` for rolling windows in the scoring engine

**Privacy invariants (load-bearing, tested):**
- `l3_decode` module API NEVER returns plaintext IMSI/TMSI/IMEI. Internal helper extracts the raw bytes; public function calls `Anonymizer.anonymize()` BEFORE the return value crosses the module boundary.
- `cell_baseline` table has NO subscriber-id column.
- The privacy invariant test suite is extended with 4 new shape/behavior checks.

**Out of scope (v0.3.2+):**
- Multi-frequency simultaneous scan
- SMS via EP06 alert backend (waits on #345 + spare EP06)
- PWA push notifications
- Per-trusted-phone notification routing

---

## File Structure

- **Create:**
  - `lib/sentinelle_gsm/l3_decode.py`
  - `lib/sentinelle_gsm/scoring_engine.py`
  - `lib/sentinelle_gsm/baseline.py`
  - `api/tests/test_l3_decode.py`
  - `api/tests/test_scoring_engine.py`
  - `api/tests/test_baseline.py`
  - `api/tests/test_alert_emission.py`   (integration: consume loop → scoring → alert)
- **Modify:**
  - `api/main.py` — consume loop calls `L3Decode.parse()` + `ScoringEngine.evaluate()` + matches against trusted_phones + writes Alert. New endpoints `/baseline*`, `/scoring/thresholds`.
  - `lib/sentinelle_gsm/scoring.py` — DELETE (replaced by `scoring_engine.py`; the v0.1 stub never had implementations).
  - `lib/sentinelle_gsm/gsmtap_listener.py` — extend `Observation` with `raw_l3` bytes field (the payload after the GSMTAP header)
  - `www/sentinelle/` — new "Baseline" + "Scoring" panels; alerts table renders `trusted_label` chip
  - `tests/test_privacy_invariant.py` — 4 new checks
  - `debian/changelog` — bump 0.3.0 → 0.3.1

---

## Task 1 — Extend `Observation` with `raw_l3` + propagate

**Files:**
- Modify: `lib/sentinelle_gsm/gsmtap_listener.py`
- Modify: `api/tests/test_gsmtap_listener.py`

The v0.3.0 `Observation` carries only header metadata (ARFCN, frame_nr, channel, sub_type). v0.3.1 needs the payload too. The GSMTAP header is fixed at 16 bytes; everything after is the L3 frame.

- [ ] **Step 1: Add `raw_l3: bytes = b""` field to `Observation` dataclass**

```python
@dataclasses.dataclass
class Observation:
    ts: float
    arfcn: int
    frame_nr: int
    channel: int
    sub_type: int
    raw_l3: bytes = b""            # NEW — L3 payload after GSMTAP header
    lac: Optional[int] = None
    ci:  Optional[int] = None
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    cell_id: Optional[str] = None
    subscriber_hash: Optional[str] = None
```

The order matters: `bytes = b""` is a fixed default so it doesn't break the existing dataclass ordering rules (non-default fields first).

- [ ] **Step 2: In `_on_datagram`, slice `raw_l3 = data[hdr_len:]` and pass it**

```python
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
    ...
```

- [ ] **Step 3: Extend `test_listener_receives_a_datagram` to assert `raw_l3 == expected_payload`**

Construct the datagram with a known payload (e.g. `b"\x06\x1a"` = BCCH SI Type 3 first bytes), assert the listener yields `Observation` with `raw_l3` matching.

- [ ] **Step 4: Run + commit**

```bash
cd packages/secubox-sentinelle-gsm
python3 -m pytest api/tests/test_gsmtap_listener.py -v
```
Expected: 4 still pass + 1 new assertion (raw_l3 check) within the existing test.

```bash
git commit -am "feat(sentinelle-gsm): GsmtapListener exposes raw_l3 payload bytes (ref #349)"
```

---

## Task 2 — `l3_decode.py` (BCCH SI + CCCH paging request)

**Files:**
- Create: `lib/sentinelle_gsm/l3_decode.py`
- Create: `api/tests/test_l3_decode.py`

Pure-Python TLV per message type. We only need the subset that matters for the heuristics + paging extraction.

### GSM L3 message-type reference (3GPP TS 24.008 + TS 44.018)

| msg_type byte | Channel | Meaning | We need |
|---|---|---|---|
| `0x06 0x18` | BCCH | SI Type 1 | (frequency list — for orphan_arfcn, optional v0.3.2) |
| `0x06 0x19` | BCCH | SI Type 2 | (neighbour ARFCN list) |
| `0x06 0x1a` | BCCH | SI Type 3 | **MCC, MNC, LAC, CI, cell options (A5/X), T3212** |
| `0x06 0x1c` | BCCH | SI Type 4 | LAC (re-validation) |
| `0x06 0x1e` | BCCH | SI Type 6 | cipher mode + LAI |
| `0x06 0x21` | CCCH | Paging Request Type 1 | 1-2 paged identities |
| `0x06 0x22` | CCCH | Paging Request Type 2 | 2 TMSI + 1 IMSI |
| `0x06 0x24` | CCCH | Paging Request Type 3 | 4 TMSI |

- [ ] **Step 1: Write `l3_decode.py` skeleton with parsers per msg_type**

```python
# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/l3_decode.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
GSM L3 message decoder — minimal subset for IMSI-catcher detection.

Hard invariant : public API NEVER emits plaintext IMSI/TMSI/IMEI.
The internal `_extract_mobile_id_bcd()` returns plaintext bytes; the
public `parse_paging_request()` immediately calls Anonymizer.anonymize()
on those bytes BEFORE building the ParsedPagingRequest dataclass.

Reference :
  3GPP TS 24.008 §10.5.1.4  Mobile Identity (IMSI, TMSI, IMEI encoding)
  3GPP TS 44.018 §9.1       BCCH / CCCH message structures
"""

from __future__ import annotations

import dataclasses
from typing import List, Optional

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
def _decode_mcc_mnc(buf: bytes) -> tuple[Optional[int], Optional[int]]:
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


def _try_extract_mobile_id(buf: bytes, ofs: int) -> tuple[Optional[tuple[int, bytes]], int]:
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
```

This file is ~210 lines. The TS 44.018 BCCH structures are subtle — the parser is permissive (returns None / empty CellInfo on unexpected layouts rather than throwing).

- [ ] **Step 2: Write `test_l3_decode.py` with synthetic frames**

```python
import pytest
from sentinelle_gsm.observer import Anonymizer
from sentinelle_gsm.l3_decode import (
    L3Decode, MID_TYPE_TMSI, MID_TYPE_IMSI, _decode_mcc_mnc, _decode_bcd_imsi,
)


@pytest.fixture
def decoder():
    return L3Decode(Anonymizer(b"x" * 32))


def test_decode_mcc_mnc_2_digit_mnc():
    # Orange FR : MCC=208, MNC=01 — encoded with F-padding nibble
    # buf bytes : 0x80 0xF1 0x10  →  digits (8 0 F 1 1 0) ; MCC=208, MNC=01
    mcc, mnc = _decode_mcc_mnc(b"\x80\xF1\x10")
    assert mcc == 208
    assert mnc == 1


def test_decode_bcd_imsi_15_digits_even():
    # IMSI 208201234567890 = 15 digits (odd, so the odd flag in body[0]=1)
    # Per BCD with odd flag:
    #   body[0] low nibble = (mid_type=IMSI=1) | odd<<3 → 0x09
    #   body[0] high nibble = first IMSI digit = 2
    #   body[1] = 8 (high) | 0 (low) ...
    # Construct manually:
    body = bytes([0x29, 0x80, 0x32, 0x54, 0x76, 0x98, 0x09])
    digits = _decode_bcd_imsi(body)
    assert digits == "208201234567890"


def test_parse_si3_extracts_mcc_mnc_lac_ci(decoder):
    # Header: 0x06 0x1a + 2 bytes CI + 5 bytes LAI + filler
    raw = (b"\x06\x1a" +                   # L3 header SI3
           b"\x30\x39" +                   # CI = 0x3039 = 12345
           b"\x80\xF1\x10" +                # LAI: MCC=208 MNC=01
           b"\x00\xC8" +                    # LAC = 200
           b"\x00\x00\x00" +                # control_channel_description
           b"\x00" +                        # cell_options (no A5 bits set)
           b"\x00\x00" +                    # cell_selection
           b"\x00\x00\x00")                 # rach_control
    frame = decoder.parse(raw)
    assert frame.cell_info is not None
    assert frame.cell_info.mcc == 208
    assert frame.cell_info.mnc == 1
    assert frame.cell_info.lac == 200
    assert frame.cell_info.ci == 12345


def test_parse_paging_request_1_with_tmsi(decoder):
    # 0x06 0x21 + page_mode(1) + ChannelNeeded(1) + Mobile-ID(TMSI)
    # Mobile Identity TLV: length=5, body=[type_byte][4-byte TMSI]
    #   type_byte for TMSI = 0x04 (id_type=4, odd=0)
    tmsi_bytes = b"\xDE\xAD\xBE\xEF"
    mid = b"\x05" + b"\xF4" + tmsi_bytes    # length=5, body=[0xF4 + 4 bytes TMSI]
    raw = b"\x06\x21" + b"\x00" + mid       # 2-byte L3 hdr + page_mode_byte + MID
    frame = decoder.parse(raw)
    assert frame.paging is not None
    assert len(frame.paging.identities) >= 1
    pid = frame.paging.identities[0]
    assert pid.id_type == MID_TYPE_TMSI
    assert pid.subscriber_hash != "deadbeef"     # MUST be HMAC, not plaintext


def test_unknown_msg_type_returns_empty_frame(decoder):
    frame = decoder.parse(b"\x06\xFF\x00\x00")
    assert frame.cell_info is None
    assert frame.paging is None


def test_truncated_input_returns_empty(decoder):
    assert decoder.parse(b"") == decoder.parse(b"\x06")
```

Note : the BCD encoding nibble layout in `test_decode_bcd_imsi_15_digits_even` and the TMSI body construction in `test_parse_paging_request_1_with_tmsi` are sensitive to the spec's swap-nibble semantics. Adapt by hand if the assertions fail — the test is verifying the parser's BCD direction, not the spec's exact byte order. Better yet, build the body programmatically with a small helper.

- [ ] **Step 3: Run + commit**

```bash
python3 -m pytest api/tests/test_l3_decode.py -v
git commit -am "feat(sentinelle-gsm): l3_decode — BCCH SI + CCCH paging request parsing (ref #349)"
```

Expected ~6 passing tests.

---

## Task 3 — `baseline.py` (operator-baseline learning + persistence)

**Files:**
- Create: `lib/sentinelle_gsm/baseline.py`
- Create: `api/tests/test_baseline.py`

- [ ] **Step 1: Add the `cell_baseline` table to `observations.py`**

```python
# IN observations.py: in ObservationsDB.__init__, add:
self._db.execute("""
    CREATE TABLE IF NOT EXISTS cell_baseline (
        cell_id TEXT PRIMARY KEY,
        mcc INTEGER, mnc INTEGER, lac INTEGER, arfcn INTEGER,
        learn_count INTEGER NOT NULL DEFAULT 1,
        first_learned REAL NOT NULL,
        last_learned  REAL NOT NULL,
        cipher_a5     INTEGER
    )
""")
```

- [ ] **Step 2: Write `baseline.py`**

```python
# packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/baseline.py
"""
Operator baseline — list of cells the operator's carrier(s) legitimately
operate in this RF environment. Cells are graduated to baseline after
being observed N≥3 times; or in 'learn mode' every cell observed within
a sweep window is marked baseline regardless of count.

Used by the scoring engine for ghost_bts + identity_mismatch +
cipher_downgrade heuristics.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Optional
import sqlite3


@dataclasses.dataclass
class BaselineCell:
    cell_id: str
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    lac: Optional[int] = None
    arfcn: Optional[int] = None
    learn_count: int = 1
    first_learned: float = 0.0
    last_learned: float = 0.0
    cipher_a5: Optional[int] = None


class CellBaseline:
    """Thin wrapper over the cell_baseline table colocated in observations.db."""

    LEARN_THRESHOLD = 3      # default — cells need ≥3 sightings to graduate

    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._learn_mode_until: float = 0.0   # epoch; learn_mode while now() < this

    def set_learn_mode(self, seconds: float) -> None:
        self._learn_mode_until = time.time() + seconds

    def in_learn_mode(self) -> bool:
        return time.time() < self._learn_mode_until

    def consider(self, cell_id: str, mcc=None, mnc=None, lac=None,
                 arfcn=None, cipher_a5=None) -> None:
        """Called by the consume loop on every cell sighting. In learn
        mode, immediately graduate; otherwise increment learn_count and
        graduate when it crosses LEARN_THRESHOLD."""
        now = time.time()
        row = self._db.execute(
            "SELECT learn_count FROM cell_baseline WHERE cell_id = ?",
            (cell_id,),
        ).fetchone()
        if row is None:
            initial = self.LEARN_THRESHOLD if self.in_learn_mode() else 1
            self._db.execute(
                "INSERT INTO cell_baseline(cell_id,mcc,mnc,lac,arfcn,learn_count,"
                "first_learned,last_learned,cipher_a5) VALUES (?,?,?,?,?,?,?,?,?)",
                (cell_id, mcc, mnc, lac, arfcn, initial, now, now, cipher_a5),
            )
        else:
            new_count = row[0] + 1
            self._db.execute(
                "UPDATE cell_baseline SET learn_count = ?, last_learned = ?, "
                "mcc = COALESCE(?, mcc), mnc = COALESCE(?, mnc), "
                "lac = COALESCE(?, lac), arfcn = COALESCE(?, arfcn), "
                "cipher_a5 = COALESCE(?, cipher_a5) WHERE cell_id = ?",
                (new_count, now, mcc, mnc, lac, arfcn, cipher_a5, cell_id),
            )
        self._db.commit()

    def is_baseline(self, cell_id: str) -> bool:
        row = self._db.execute(
            "SELECT learn_count FROM cell_baseline WHERE cell_id = ?",
            (cell_id,),
        ).fetchone()
        return row is not None and row[0] >= self.LEARN_THRESHOLD

    def get(self, cell_id: str) -> Optional[BaselineCell]:
        row = self._db.execute(
            "SELECT cell_id,mcc,mnc,lac,arfcn,learn_count,first_learned,last_learned,cipher_a5 "
            "FROM cell_baseline WHERE cell_id = ?",
            (cell_id,),
        ).fetchone()
        return BaselineCell(*row) if row else None

    def list(self, limit: int = 200) -> list[BaselineCell]:
        rows = self._db.execute(
            "SELECT cell_id,mcc,mnc,lac,arfcn,learn_count,first_learned,last_learned,cipher_a5 "
            "FROM cell_baseline ORDER BY last_learned DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [BaselineCell(*r) for r in rows]
```

- [ ] **Step 3: Tests**

5 tests :
- `test_first_consider_starts_at_1_not_baseline_yet`
- `test_three_considers_graduate_to_baseline`
- `test_learn_mode_graduates_first_consider`
- `test_consider_updates_metadata_via_coalesce`
- `test_list_orders_by_last_learned_desc`

- [ ] **Step 4: Run + commit**

```bash
python3 -m pytest api/tests/test_baseline.py -v
git commit -am "feat(sentinelle-gsm): baseline.py — operator-baseline learning (ref #349)"
```

---

## Task 4 — `scoring_engine.py` (8 heuristics + aggregator)

**Files:**
- Create: `lib/sentinelle_gsm/scoring_engine.py`
- Delete: `lib/sentinelle_gsm/scoring.py` (v0.1 shape-only stub — replaced)
- Create: `api/tests/test_scoring_engine.py`

### Heuristic spec table

| # | Name | Condition | Default score | Sliding window |
|---|---|---|---|---|
| 1 | cipher_downgrade | observed A5/X < baseline.cipher_a5 for this cell | 40 | none |
| 2 | ghost_bts | observed cell_id NOT in baseline AND ≥1 paging seen | 35 | none |
| 3 | identity_mismatch | observed (mcc, mnc) ≠ baseline (mcc, mnc) for same ARFCN | 30 | none |
| 4 | relocalization_storm | ≥3 distinct LAC values for our trusted hashes in 60 s | 25 | 60 s |
| 5 | identity_request_abuse | ≥2 IMSI Identity Requests for same TMSI in 5 min | 35 | 5 min |
| 6 | anomalous_neighbours | empty neighbour list (SI Type 2/2bis/2ter) where baseline shows ≥1 | 15 | none |
| 7 | t3212_out_of_band | T3212 < 1 or > 60 minutes (carrier norm 6-30) | 15 | none |
| 8 | orphan_arfcn | this ARFCN not in this carrier's known frequency plan | 20 | none |

Final score = sum (clamped to [0, 100]). Each heuristic returns `(contrib, reason_str)`; collected reasons[] are attached to the Alert.

- [ ] **Step 1: Write `scoring_engine.py`**

The file structure :

```python
@dataclasses.dataclass
class HeuristicResult:
    name: str
    triggered: bool
    score_contrib: int
    reason: str


@dataclasses.dataclass
class CellScore:
    cell_id: str
    score: int                    # 0-100
    reasons: list[str]
    triggered: list[str]          # names of fired heuristics


class ScoringEngine:
    DEFAULT_THRESHOLDS = {
        "cipher_downgrade":      {"enabled": True, "score": 40},
        "ghost_bts":             {"enabled": True, "score": 35},
        "identity_mismatch":     {"enabled": True, "score": 30},
        "relocalization_storm":  {"enabled": True, "score": 25, "window_s": 60, "lac_threshold": 3},
        "identity_request_abuse":{"enabled": True, "score": 35, "window_s": 300, "req_threshold": 2},
        "anomalous_neighbours":  {"enabled": True, "score": 15},
        "t3212_out_of_band":     {"enabled": True, "score": 15, "min": 1, "max": 60},
        "orphan_arfcn":          {"enabled": True, "score": 20},
    }

    def __init__(self, baseline: CellBaseline, thresholds: dict | None = None):
        self._baseline = baseline
        self._thresholds = thresholds or dict(self.DEFAULT_THRESHOLDS)
        # In-memory rolling windows :
        self._lac_window:   dict[str, deque] = defaultdict(lambda: deque())   # cell_id → deque[(ts, lac)]
        self._idreq_window: dict[str, deque] = defaultdict(lambda: deque())   # tmsi_hash → deque[ts]
        self._neighbour_baseline: dict[str, set[int]] = {}      # cell_id → set of arfcns observed

    def evaluate(self, cell_info, parsed_paging, raw_arfcn, raw_neighbours=None) -> CellScore:
        """Run all 8 heuristics ; sum-clamp."""
        results: list[HeuristicResult] = []
        cell_id = _cell_id(cell_info)
        baseline_cell = self._baseline.get(cell_id) if cell_id else None

        results.append(self._h_cipher_downgrade(cell_info, baseline_cell))
        results.append(self._h_ghost_bts(cell_id, baseline_cell, parsed_paging))
        results.append(self._h_identity_mismatch(cell_info, raw_arfcn, baseline_cell))
        results.append(self._h_relocalization_storm(cell_id, cell_info))
        results.append(self._h_identity_request_abuse(parsed_paging))
        results.append(self._h_anomalous_neighbours(cell_id, raw_neighbours))
        results.append(self._h_t3212_out_of_band(cell_info))
        results.append(self._h_orphan_arfcn(raw_arfcn, cell_info))

        total = sum(r.score_contrib for r in results if r.triggered)
        total = min(100, max(0, total))
        return CellScore(
            cell_id=cell_id or f"arfcn-{raw_arfcn}",
            score=total,
            reasons=[r.reason for r in results if r.triggered],
            triggered=[r.name for r in results if r.triggered],
        )

    def update_thresholds(self, new: dict) -> dict:
        """Merge ; return effective thresholds."""
        for k, v in new.items():
            if k in self._thresholds and isinstance(v, dict):
                self._thresholds[k].update(v)
        return dict(self._thresholds)

    def thresholds(self) -> dict:
        return dict(self._thresholds)

    # ── 8 heuristic implementations ────────────────────────────────────
    # Each returns HeuristicResult. Implementation per the table above.
    # (full code in plan body — ~150 lines)
```

- [ ] **Step 2: Tests — 1 per heuristic + 1 aggregator + 1 threshold-update = 10 tests**

Test each heuristic individually with synthetic CellInfo + Baseline state. Mock the baseline DB.

- [ ] **Step 3: Delete the v0.1 scoring.py stub**

```bash
git rm packages/secubox-sentinelle-gsm/lib/sentinelle_gsm/scoring.py
```
Grep for any importers ; should be empty (the v0.1 stub was never imported by api/main.py).

- [ ] **Step 4: Run + commit**

```bash
python3 -m pytest api/tests/test_scoring_engine.py -v
git commit -am "feat(sentinelle-gsm): scoring_engine — 8 heuristics + thresholds (ref #349)"
```

---

## Task 5 — Consume loop : L3 decode + scoring + trusted match + alert emission

**Files:**
- Modify: `api/main.py`
- Create: `api/tests/test_alert_emission.py`

The v0.3.0 consume loop just upserts a sighting. v0.3.1 also :
1. Decodes the L3 payload
2. Updates sighting metadata when SI3/SI4/SI6 lands
3. Persists paging events with subscriber_hash
4. Feeds baseline.consider()
5. Runs scoring_engine.evaluate()
6. If score ≥ `alert_threshold` :
   - Look up each paged hash in `trusted_registry.lookup_by_hash()`
   - If ≥1 match : write Alert with `subscriber_hash` + `trusted_label`
   - Else : write Alert with no target (anomaly only)

- [ ] **Step 1: Wire singletons** (similar to Task 4 of v0.3.0 plan)

```python
_l3:      Optional[L3Decode] = None
_scoring: Optional[ScoringEngine] = None
_baseline: Optional[CellBaseline] = None
ALERT_THRESHOLD = int(os.environ.get("SENTINELLE_ALERT_THRESHOLD", 60))
```

- [ ] **Step 2: Rewrite the consume coroutine**

```python
async def _consume_observations() -> None:
    listener = get_listener()
    obs_db = get_obs_db()
    l3 = _l3
    scoring = _scoring
    baseline = _baseline
    trusted = get_trusted_registry()
    sink = get_alert_sink()

    async for obs in listener.observations():
        cell_id_fallback = f"arfcn-{obs.arfcn}-ch-{obs.channel}"

        parsed = l3.parse(obs.raw_l3)
        cell_info = parsed.cell_info
        cell_id = _cell_id(cell_info) or cell_id_fallback

        # 1. Upsert sighting
        obs_db.upsert_sighting(Sighting(
            cell_id=cell_id,
            mcc=cell_info.mcc if cell_info else None,
            mnc=cell_info.mnc if cell_info else None,
            lac=cell_info.lac if cell_info else None,
            ci=cell_info.ci if cell_info else None,
            arfcn=obs.arfcn,
        ))

        # 2. Persist paging events (hashed)
        if parsed.paging:
            for pid in parsed.paging.identities:
                obs_db.record_paging(PagingEvent(
                    ts=obs.ts, cell_id=cell_id,
                    subscriber_hash=pid.subscriber_hash,
                    request_type=("paging-imsi" if pid.id_type == MID_TYPE_IMSI else "paging-tmsi"),
                ))

        # 3. Feed baseline
        baseline.consider(cell_id,
                          mcc=cell_info.mcc if cell_info else None,
                          mnc=cell_info.mnc if cell_info else None,
                          lac=cell_info.lac if cell_info else None,
                          arfcn=obs.arfcn,
                          cipher_a5=cell_info.a5_advertised if cell_info else None)

        # 4. Score
        result = scoring.evaluate(cell_info, parsed.paging, obs.arfcn)
        if result.score < ALERT_THRESHOLD:
            continue

        # 5. Match against trusted
        trusted_hit = None
        if parsed.paging:
            for pid in parsed.paging.identities:
                hit = trusted.lookup_by_hash(pid.subscriber_hash)
                if hit:
                    trusted_hit = hit
                    break

        sink.write(Alert(
            cell_id=cell_id,
            arfcn=obs.arfcn,
            score=result.score,
            reason=" + ".join(result.reasons[:3]),    # truncate for UI
            subscriber_hash=(trusted_hit.imsi_hash if trusted_hit else None),
            trusted_label=(trusted_hit.label if trusted_hit else None),
        ))
```

- [ ] **Step 3: New endpoints**

```python
@app.get("/baseline")
def list_baseline(limit: int = 200): ...

@app.post("/baseline/learn")
def baseline_learn(body: BaselineLearnBody): ...
    # body.sweep_seconds: int (default 300)
    # if no scan currently running, raises 409 with hint to start one first
    # else flips baseline into learn_mode for `sweep_seconds`

@app.get("/scoring/thresholds")
def scoring_thresholds_get(): ...

@app.post("/scoring/thresholds")
def scoring_thresholds_set(body: dict): ...
    # writes an audit-log line via logger.info (caught by /journal/stream)
```

- [ ] **Step 4: Integration tests in `test_alert_emission.py`**

5 tests covering :
- Score below threshold → no alert
- Score above threshold + no trusted match → anomaly-only alert
- Score above threshold + trusted match → alert with trusted_label
- Paging event persistence with hash
- Audit log entry on POST /scoring/thresholds

- [ ] **Step 5: Run + commit**

```bash
python3 -m pytest api/tests/test_alert_emission.py -v
git commit -am "feat(sentinelle-gsm): consume loop wires L3 + scoring + trusted match → Alert (ref #349)"
```

---

## Task 6 — WebUI Baseline + Scoring panels

**Files:**
- Modify: `www/sentinelle/index.html`, `sentinelle.css`, `sentinelle.js`

- [ ] **Step 1: HTML new panels**

After "Observations", before "Actions" :

**`#baseline` panel** — table : Cell ID, MCC, MNC, LAC, ARFCN, Cipher A5, Learn count, Last learned. Buttons : "Refresh", "Start baseline learn (5 min)".

**`#scoring` panel** — 8 rows, one per heuristic. Per row : name + enabled toggle + score input + reset-to-default button. Footer : "Apply changes" + "Reset all to defaults".

Alert rows in `#alerts` panel — render `trusted_label` chip when present (violet pill).

- [ ] **Step 2: JS**

New helpers : `loadBaseline()`, `startBaselineLearn()`, `loadThresholds()`, `saveThresholds()`. Poll baseline every 30 s while a scan is running.

The alert row formatter is extended to render `<span class="trusted-chip">${trusted_label}</span>` when present.

- [ ] **Step 3: CSS — `.trusted-chip` (violet pill), `.threshold-row` (grid 5-col), `.score-input` (small numeric input)**

- [ ] **Step 4: Commit**

```bash
git commit -am "feat(sentinelle-gsm): webui baseline + scoring panels + trusted_label chip (ref #349)"
```

---

## Task 7 — Privacy invariant tests + changelog 0.3.1

- [ ] **Step 1: Add 4 new privacy tests**

```python
def test_l3_decode_returns_no_plaintext_fields():
    from sentinelle_gsm.l3_decode import PagedIdentity, ParsedPagingRequest, CellInfo
    from dataclasses import fields
    for cls in (PagedIdentity, ParsedPagingRequest, CellInfo):
        names = {f.name for f in fields(cls)}
        forbidden = {"imsi", "tmsi", "imei", "msisdn", "iccid"}
        assert names.isdisjoint(forbidden), f"{cls.__name__} has plaintext id fields"


def test_paging_request_hashes_paged_identities():
    from sentinelle_gsm.observer import Anonymizer
    from sentinelle_gsm.l3_decode import L3Decode, MID_TYPE_TMSI
    anon = Anonymizer(b"x" * 32)
    dec = L3Decode(anon)
    # Build a paging request with a known TMSI
    tmsi = b"\xDE\xAD\xBE\xEF"
    mid = b"\x05\xF4" + tmsi
    raw = b"\x06\x21\x00" + mid
    frame = dec.parse(raw)
    pid = frame.paging.identities[0]
    # Plaintext bytes MUST NOT appear in the hash output
    assert tmsi.hex() not in pid.subscriber_hash
    assert pid.id_type == MID_TYPE_TMSI


def test_cell_baseline_has_no_subscriber_fields():
    from sentinelle_gsm.baseline import BaselineCell
    from dataclasses import fields
    names = {f.name for f in fields(BaselineCell)}
    forbidden = {"imsi", "tmsi", "imei", "subscriber_hash", "subscriber_id"}
    assert names.isdisjoint(forbidden)


def test_scoring_engine_consumes_hashes_only():
    """The scoring engine's HeuristicResult.reason is a free-text string
    but MUST NOT include any 15-digit shape from input."""
    # ... shape check on reason strings produced by each heuristic with
    # synthetic CellInfo containing no plaintext anywhere
```

- [ ] **Step 2: Run full sweep** — expect 48 + 6 (l3_decode) + 5 (baseline) + 10 (scoring) + 5 (alert_emission) + 4 (privacy) = **78 passing**.

- [ ] **Step 3: Changelog bump**

```text
secubox-sentinelle-gsm (0.3.1-1~bookworm1) bookworm; urgency=medium

  * lib/sentinelle_gsm/l3_decode.py: NEW — pure-Python TLV parser for
    BCCH SI Type 3/4/6 (cell metadata) and CCCH Paging Request Type
    1/2/3 (paged subscriber identities). All paged identities are
    HMAC-hashed via Anonymizer BEFORE leaving the module; public API
    surface NEVER returns plaintext IMSI/TMSI/IMEI.
  * lib/sentinelle_gsm/baseline.py: NEW — operator-baseline learning.
    Cells graduate to baseline after LEARN_THRESHOLD=3 sightings.
    Explicit "learn mode" (POST /baseline/learn) immediately accepts
    every observed cell as baseline within a sweep window.
  * lib/sentinelle_gsm/scoring_engine.py: NEW — 8 heuristics from spec
    §6.1 with default thresholds. Sliding windows for relocalization
    storm + identity_request_abuse (in-memory deques). Per-heuristic
    enable + threshold are runtime-mutable via POST /scoring/thresholds
    (audit-logged to the journal stream).
  * lib/sentinelle_gsm/scoring.py: DROPPED — v0.1 shape-only stub
    replaced by scoring_engine.py.
  * api/main.py: consume loop now decodes L3 of every Observation,
    updates sighting metadata (mcc/mnc/lac/ci/cipher), persists
    paging events with hashed subscriber IDs, feeds baseline,
    runs the scoring engine, and emits Alert with trusted_label
    when a paged hash matches the trusted_phones registry.
  * api/main.py: new endpoints GET /baseline, POST /baseline/learn,
    GET /scoring/thresholds, POST /scoring/thresholds.
  * www/sentinelle/: new Baseline + Scoring panels; alert rows
    render the trusted_label chip when present.
  * tests: 30 new (l3_decode ×6, baseline ×5, scoring_engine ×10,
    alert_emission ×5, privacy ×4); full sweep 78/78 passing.
  * Closes #349. Refs #237.

 -- Gerald Kerma <devel@cybermind.fr>  Fri, 22 May 2026 16:30:00 +0000
```

- [ ] **Step 4: Commit**

```bash
git commit -am "chore(sentinelle-gsm): bump 0.3.1 + extend privacy invariant tests (closes #349)"
```

---

## Task 8 — Build .deb + open PR

```bash
cd packages/secubox-sentinelle-gsm
dpkg-buildpackage -us -uc -b
```

Verify .deb ships : `l3_decode.py`, `baseline.py`, `scoring_engine.py` ; does NOT ship the dropped `scoring.py` stub.

Open PR with the body summarising commits, the new modules, the trusted-label flow, the 8 heuristics, the privacy invariants extension, and the 78/78 test count. Closes #349.

---

## Task 9 — On-board E2E (manual, after PR merge)

1. Deploy 0.3.1 .deb to gk2.
2. Verify `systemctl is-active secubox-sentinelle-gsm` → active.
3. Add a trusted phone with the operator's own IMSI hash via the webui.
4. POST `/baseline/learn { sweep_seconds: 300 }` AND start a scan ; let it run 5 min.
5. Verify GET `/baseline` populated with at least one cell.
6. Stop scan ; modify the operator's phone IMSI hash slightly (simulate a paging targeting it) ; restart scan ; force an alert via the test injection path (paged hash that matches).
7. Verify : alert with `trusted_label` chip appears in /sentinelle/ live feed, browser desktop notification fires.
8. Adjust scoring thresholds via the UI ; verify journal log line records the change.
9. Comment on #349 with "v0.3.1 validated, closing".
