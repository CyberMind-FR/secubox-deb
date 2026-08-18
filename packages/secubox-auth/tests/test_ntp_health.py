# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""ntp_health: parsing, caching, fallback when chronyc missing."""
from pathlib import Path

import pytest

from api import ntp_health


SAMPLE_SYNCED = """\
Reference ID    : 8A1B0C2D (ntp.example.org)
Stratum         : 3
Ref time (UTC)  : Wed May 13 04:30:00 2026
System time     : 0.000123456 seconds fast of NTP time
Last offset     : -0.000098 seconds
RMS offset      : 0.000123 seconds
Frequency       : 12.345 ppm slow
Residual freq   : 0.001 ppm
Skew            : 1.234 ppm
Root delay      : 0.012345 seconds
Root dispersion : 0.001234 seconds
Update interval : 64.0 seconds
Leap status     : Normal
"""

SAMPLE_UNSYNCED = """\
Reference ID    : 7F7F0101 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan  1 00:00:00 1970
System time     : 0.000000000 seconds fast of NTP time
Last offset     : +0.000000000 seconds
RMS offset      : 0.000000000 seconds
Frequency       : 0.000 ppm slow
Residual freq   : +0.000 ppm
Skew            : 0.000 ppm
Root delay      : 1.000000000 seconds
Root dispersion : 1.000000000 seconds
Update interval : 0.0 seconds
Leap status     : Not synchronised
"""


@pytest.fixture(autouse=True)
def _bust_cache():
    ntp_health._cache.update({"ts": 0, "result": None})


def _fake_chronyc(stdout: str, returncode: int = 0):
    class _Proc:
        def __init__(self):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode
    def runner(*a, **kw):
        return _Proc()
    return runner


def test_synced(monkeypatch):
    monkeypatch.setattr(ntp_health.subprocess, "run", _fake_chronyc(SAMPLE_SYNCED))
    h = ntp_health.probe()
    assert h["synced"] is True
    assert h["leap_status"].lower().startswith("normal")
    assert ntp_health.recommended_totp_window() == 1


def test_unsynced(monkeypatch):
    monkeypatch.setattr(ntp_health.subprocess, "run", _fake_chronyc(SAMPLE_UNSYNCED))
    h = ntp_health.probe()
    assert h["synced"] is False
    assert ntp_health.recommended_totp_window() == 3


def test_chronyc_missing_returns_unknown(monkeypatch):
    def raise_fnf(*a, **kw):
        raise FileNotFoundError("no chronyc")
    monkeypatch.setattr(ntp_health.subprocess, "run", raise_fnf)
    h = ntp_health.probe()
    assert h["synced"] is False
    assert "error" in h
    assert ntp_health.recommended_totp_window() == 2  # unknown → middle


def test_cache_is_honoured(monkeypatch):
    calls = []
    def runner(*a, **kw):
        calls.append(1)
        class _Proc:
            stdout = SAMPLE_SYNCED
            stderr = ""
            returncode = 0
        return _Proc()
    monkeypatch.setattr(ntp_health.subprocess, "run", runner)
    ntp_health.probe()
    ntp_health.probe()
    ntp_health.probe()
    assert len(calls) == 1  # cached
