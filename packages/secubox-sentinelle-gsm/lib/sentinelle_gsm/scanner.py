# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Wraps grgsm_scanner to discover GSM cells before /scan/auto spawns a
LivemonFleet. grgsm_scanner sweeps a GSM band, decodes each ARFCN's
BCCH long enough to read MCC/MNC/LAC/CID/power, then prints one line
per cell:

    ARFCN: %4u, Freq: %6.1fM, CID: %5u, LAC: %5u, MCC: %3u, MNC: %3u, Pwr: %3i

We subprocess it, parse those lines, and return a list[CellInfo].

Two operational quirks worth knowing:

  1. grgsm_scanner hard-binds UDP 4729 (the same port our GSMTAP
     listener binds). The caller MUST stop the listener before invoking
     scan_band(). main.py's /scan/auto handler does that.
  2. grgsm_scanner accepts --args=rtl=0 (which the broken match() code
     path never sees), so we don't need the device.py shim here. The
     device.py bug only bites when --args is omitted, and we always
     pass it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import shutil
from typing import Optional


# Output line emitted by grgsm_scanner for each discovered cell.
# Generated at /usr/bin/grgsm_scanner line 558:
#   return "ARFCN: %4u, Freq: %6.1fM, CID: %5u, LAC: %5u, MCC: %3u,
#           MNC: %3u, Pwr: %3i" % (...)
_CELL_LINE_RE = re.compile(
    r"ARFCN:\s*(?P<arfcn>\d+),\s*"
    r"Freq:\s*(?P<freq>[\d.]+)M,\s*"
    r"CID:\s*(?P<cid>\d+),\s*"
    r"LAC:\s*(?P<lac>\d+),\s*"
    r"MCC:\s*(?P<mcc>\d+),\s*"
    r"MNC:\s*(?P<mnc>\d+),\s*"
    r"Pwr:\s*(?P<pwr>-?\d+)"
)


@dataclasses.dataclass(frozen=True)
class CellInfo:
    """One discovered GSM cell.

    `freq` is a CLI-friendly string ("947.4M") that LivemonRunner.start
    accepts directly. `power` is the dBm value grgsm_scanner reports —
    higher (closer to 0) = stronger signal.
    """

    arfcn: int
    freq: str
    cid: int
    lac: int
    mcc: int
    mnc: int
    power: int


def parse_scanner_output(stdout: str) -> list[CellInfo]:
    """Pull CellInfo records out of grgsm_scanner stdout.

    Ignores progress lines ("Scanning: 23.45% done.."), banner/info
    output, and any partial lines. Order preserved (scanner emits in
    ARFCN order; callers reorder by power).
    """
    cells: list[CellInfo] = []
    for line in stdout.splitlines():
        m = _CELL_LINE_RE.search(line)
        if not m:
            continue
        cells.append(
            CellInfo(
                arfcn=int(m["arfcn"]),
                freq=f"{m['freq']}M",
                cid=int(m["cid"]),
                lac=int(m["lac"]),
                mcc=int(m["mcc"]),
                mnc=int(m["mnc"]),
                power=int(m["pwr"]),
            )
        )
    return cells


def select_diverse(cells: list[CellInfo], n: int) -> list[CellInfo]:
    """Pick up to `n` cells, maximising operator spread (mcc+mnc) first
    and breaking ties by power.

    Strategy: sort by power desc, then walk the list once, taking the
    strongest cell per (mcc, mnc) until we have n; if we exhaust unique
    operators before hitting n, take the next-strongest remaining cell
    regardless of operator.

    Useful for IMSI-catcher detection: a real area has at least 3
    operators on different ARFCNs, so spreading the fleet across them
    gives the L3 scoring engine the cross-operator signal it needs
    (ghost_bts, anomalous_neighbours, identity_mismatch).
    """
    if n <= 0:
        return []
    by_power = sorted(cells, key=lambda c: -c.power)
    seen_ops: set[tuple[int, int]] = set()
    primary: list[CellInfo] = []
    remaining: list[CellInfo] = []
    for c in by_power:
        op = (c.mcc, c.mnc)
        if op in seen_ops:
            remaining.append(c)
        else:
            seen_ops.add(op)
            primary.append(c)
            if len(primary) >= n:
                break
    if len(primary) >= n:
        return primary[:n]
    # ran out of operators — pad with remaining strongest.
    return primary + remaining[: n - len(primary)]


async def scan_band(
    band: str = "GSM900",
    gain: Optional[float] = None,
    ppm: Optional[float] = None,
    samp_rate: Optional[str] = None,
    speed: Optional[int] = None,
    args: str = "rtl=0",
    timeout: float = 180.0,
) -> list[CellInfo]:
    """Run grgsm_scanner and return discovered cells.

    band: one of GSM900/DCS1800/GSM850/PCS1900/GSM450/GSM480/GSM-R.
    gain/ppm/samp_rate/speed: passed straight to grgsm_scanner.
    args: gr-osmosdr device args. Default rtl=0 forces the RTL-SDR
        backend (and dodges the device.py auto-pick path that gr-gsm
        1.0.0 mis-implements — see the shim in livemon_runner.py).
    timeout: hard kill after this many seconds. GSM900 takes ~30-90s
        in practice depending on --speed; 180s is generous.

    Prerequisite: the caller MUST ensure UDP 4729 is free (stop the
    GSMTAP listener), otherwise grgsm_scanner crashes with
    `RuntimeError: bind: Address already in use`.

    Raises:
        FileNotFoundError if grgsm_scanner isn't installed.
        asyncio.TimeoutError if it doesn't finish in `timeout` seconds.
        RuntimeError with stderr_tail on any non-zero exit.
    """
    bin_path = shutil.which("grgsm_scanner") or "/usr/bin/grgsm_scanner"
    argv = [bin_path, f"--args={args}", "-b", band]
    if gain is not None:
        argv += ["-g", str(gain)]
    if ppm is not None:
        # grgsm_scanner refuses float ppm with "invalid integer value: '60.0'".
        argv += ["-p", str(int(ppm))]
    if samp_rate is not None:
        argv += ["-s", str(samp_rate)]
    if speed is not None:
        argv += ["--speed", str(speed)]

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    if proc.returncode != 0:
        raise RuntimeError(
            f"grgsm_scanner exit {proc.returncode}: "
            f"{stderr.decode(errors='replace')[-2000:]}"
        )

    return parse_scanner_output(stdout.decode(errors="replace"))
