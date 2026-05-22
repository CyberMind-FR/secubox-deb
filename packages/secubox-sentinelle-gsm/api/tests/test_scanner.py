# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Unit tests for sentinelle_gsm.scanner — parsing + diversity selection."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelle_gsm.scanner import (
    CellInfo,
    parse_scanner_output,
    scan_band,
    select_diverse,
)


# ── parse_scanner_output ─────────────────────────────────────────────

def test_parse_one_cell():
    """The exact line format emitted by /usr/bin/grgsm_scanner line 558."""
    line = "ARFCN:  119, Freq:  947.4M, CID: 12345, LAC:   234, MCC: 208, MNC:  10, Pwr: -45"
    cells = parse_scanner_output(line)
    assert len(cells) == 1
    c = cells[0]
    assert c.arfcn == 119
    assert c.freq == "947.4M"
    assert c.cid == 12345
    assert c.lac == 234
    assert c.mcc == 208
    assert c.mnc == 10
    assert c.power == -45


def test_parse_multiple_cells_mixed_with_noise():
    """Real-world output: banner lines, progress lines, partial lines, then cells."""
    out = """
Args= rtl=0
Wide bandwidth: 10.0 MHz
Try scan CCCH on 1-124 arfcn`s:
Scanning: 23.45% done..
Scanning: 78.90% done..

ARFCN:   73, Freq:  939.6M, CID:   100, LAC:   200, MCC: 208, MNC:   1, Pwr: -55
ARFCN:  119, Freq:  947.4M, CID: 12345, LAC:   234, MCC: 208, MNC:  10, Pwr: -45
ARFCN:    1, Freq:  935.2M, CID:    50, LAC:   100, MCC: 208, MNC:  20, Pwr: -65
"""
    cells = parse_scanner_output(out)
    assert len(cells) == 3
    assert [c.arfcn for c in cells] == [73, 119, 1]
    assert [c.mnc for c in cells] == [1, 10, 20]


def test_parse_empty_output():
    assert parse_scanner_output("") == []
    assert parse_scanner_output("no cells found\n") == []


def test_parse_partial_line_skipped():
    """Truncated lines must NOT produce half-populated CellInfo."""
    bad = "ARFCN:  119, Freq:  947.4M, CID: 12345, LAC:   234"  # no MCC/MNC/Pwr
    assert parse_scanner_output(bad) == []


def test_parse_positive_power():
    """Power can also be positive (rare; close-quarters or scanner config)."""
    line = "ARFCN:   1, Freq:  935.2M, CID:    1, LAC:    1, MCC: 208, MNC:   1, Pwr:  10"
    cells = parse_scanner_output(line)
    assert cells[0].power == 10


# ── select_diverse ───────────────────────────────────────────────────

def _cell(arfcn: int, mcc: int, mnc: int, power: int) -> CellInfo:
    return CellInfo(arfcn=arfcn, freq=f"{900+arfcn/10}M", cid=arfcn, lac=1,
                    mcc=mcc, mnc=mnc, power=power)


def test_select_diverse_picks_one_per_operator():
    """Three operators present, n=3 → one from each, strongest first."""
    cells = [
        _cell(1, 208, 1, -70),   # Orange, weak
        _cell(2, 208, 1, -50),   # Orange, strong (preferred)
        _cell(3, 208, 10, -60),  # SFR
        _cell(4, 208, 20, -55),  # Bouygues
    ]
    chosen = select_diverse(cells, 3)
    assert len(chosen) == 3
    # Strongest per operator: Orange ARFCN 2, Bouygues 4, SFR 3 (by power desc)
    assert chosen[0].arfcn == 2  # power=-50, strongest overall
    assert {c.mnc for c in chosen} == {1, 10, 20}


def test_select_diverse_falls_back_when_operators_exhausted():
    """Only 2 operators, n=4 → 2 strongest unique + 2 next-strongest."""
    cells = [
        _cell(1, 208, 1, -50),   # Orange A
        _cell(2, 208, 1, -55),   # Orange B
        _cell(3, 208, 10, -60),  # SFR A
        _cell(4, 208, 10, -65),  # SFR B
    ]
    chosen = select_diverse(cells, 4)
    assert len(chosen) == 4
    # First two: strongest from each operator (Orange ARFCN 1, SFR ARFCN 3)
    # Next two: remaining strongest (Orange ARFCN 2, SFR ARFCN 4)
    assert chosen[0].arfcn == 1
    assert chosen[1].arfcn == 3
    assert set(c.arfcn for c in chosen[2:]) == {2, 4}


def test_select_diverse_n_zero():
    assert select_diverse([_cell(1, 208, 1, -50)], 0) == []


def test_select_diverse_n_larger_than_list():
    cells = [_cell(1, 208, 1, -50)]
    chosen = select_diverse(cells, 5)
    assert chosen == cells


# ── scan_band (subprocess wrapper) ───────────────────────────────────

@pytest.mark.asyncio
async def test_scan_band_parses_stdout():
    """Mocked grgsm_scanner stdout flows through to parse_scanner_output."""
    fake = MagicMock(spec=asyncio.subprocess.Process)
    fake.returncode = 0
    fake.communicate = AsyncMock(return_value=(
        b"ARFCN:  119, Freq:  947.4M, CID: 12345, LAC:   234, MCC: 208, MNC:  10, Pwr: -45\n",
        b"",
    ))
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)):
        cells = await scan_band(band="GSM900")
    assert len(cells) == 1
    assert cells[0].arfcn == 119


@pytest.mark.asyncio
async def test_scan_band_argv_default_args():
    """--args=rtl=0 is the default — we always force the RTL-SDR backend.
    grgsm_scanner accepts this where livemon rejects it (different code
    paths)."""
    fake = MagicMock(spec=asyncio.subprocess.Process)
    fake.returncode = 0
    fake.communicate = AsyncMock(return_value=(b"", b""))
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)) as mck:
        await scan_band(band="GSM900", gain=45, ppm=10, speed=20)
    args = mck.call_args[0]
    assert "--args=rtl=0" in args
    assert "-b" in args and "GSM900" in args
    assert "-g" in args and "45" in args
    assert "-p" in args and "10" in args
    assert "--speed" in args and "20" in args


@pytest.mark.asyncio
async def test_scan_band_raises_on_nonzero_exit():
    """Surface scanner crashes so /scan/auto can return a real error."""
    fake = MagicMock(spec=asyncio.subprocess.Process)
    fake.returncode = 1
    fake.communicate = AsyncMock(return_value=(b"", b"some scanner failure"))
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)):
        with pytest.raises(RuntimeError, match="exit 1"):
            await scan_band(band="GSM900")


@pytest.mark.asyncio
async def test_scan_band_timeout_kills_proc():
    """When scanner hangs past the timeout, we kill it and raise."""
    fake = MagicMock(spec=asyncio.subprocess.Process)
    fake.returncode = None
    fake.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    fake.kill = MagicMock()
    fake.wait = AsyncMock(return_value=-9)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)):
        with pytest.raises(asyncio.TimeoutError):
            await scan_band(band="GSM900", timeout=0.01)
    fake.kill.assert_called_once()
