# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Tests for RdsRunner — without spawning rtl_fm or redsea.

We can't run the actual pipeline in CI (no RTL-SDR, no FM signal), so the
useful coverage is the parts that don't need real RF:
  - default status() before any start()
  - RdsFrame defaults
  - JSON line parsing via the internal reader path (we feed a fake
    redsea_proc.stdout that yields canned lines, then run the reader
    coroutine until exhaustion)
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from sentinelle_gsm.rds_runner import RdsFrame, RdsRunner, RdsStatus


def test_initial_status_is_idle():
    r = RdsRunner()
    st = r.status()
    assert isinstance(st, RdsStatus)
    assert st.running is False
    assert st.pid is None
    assert st.freq is None
    assert st.frames == 0
    assert st.last_pi is None and st.last_ps is None


def test_rdsframe_defaults():
    f = RdsFrame()
    assert f.pi is None
    assert f.ps is None
    assert f.rt is None
    assert f.tp is None and f.ta is None
    assert f.pty is None
    assert f.af == []


class _FakeReader:
    """Replace asyncio.StreamReader.readline() with a deterministic sequence
    of byte strings, ending with b'' to signal EOF (matches redsea closing
    stdout cleanly on -e exit)."""

    def __init__(self, lines):
        self._lines = list(lines) + [b""]
        self._i = 0

    async def readline(self):
        await asyncio.sleep(0)
        line = self._lines[self._i]
        self._i = min(self._i + 1, len(self._lines) - 1)
        return line


class _FakeProc:
    def __init__(self, reader):
        self.stdout = reader


def _run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def test_read_frames_parses_jsonlines_and_updates_counters():
    captured = []

    async def cb(frame, freq):
        captured.append((frame, freq))

    r = RdsRunner(on_frame=cb)
    # Inject fake state so _read_frames believes it's mid-run.
    r._redsea_proc = _FakeProc(_FakeReader([
        json.dumps({"pi": "F201", "ps": "FRANCE I"}).encode() + b"\n",
        b"not json at all\n",                         # ignored, no crash
        json.dumps({"pi": "F201", "rt": "Bonjour"}).encode() + b"\n",
        json.dumps({"pi": "F202", "ps": "EUROPE 1"}).encode() + b"\n",
    ]))
    r._freq = "100.6M"

    _run(r._read_frames())

    assert r._frame_count == 3
    # last_* track the LATEST seen — F202 / EUROPE 1
    assert r._last_pi == "F202"
    assert r._last_ps == "EUROPE 1"
    # callback was invoked 3 times with the current freq
    assert len(captured) == 3
    assert all(freq == "100.6M" for _, freq in captured)
    assert captured[0][0].ps == "FRANCE I"


def test_read_frames_swallows_callback_exceptions():
    """A misbehaving consumer must NOT take the runner down with it —
    the runner stays alive so the next frame still lands in the DB."""
    async def cb(frame, freq):
        raise RuntimeError("boom")

    r = RdsRunner(on_frame=cb)
    r._redsea_proc = _FakeProc(_FakeReader([
        json.dumps({"pi": "F201"}).encode() + b"\n",
        json.dumps({"pi": "F202"}).encode() + b"\n",
    ]))
    r._freq = "100.0M"
    # Should NOT raise.
    _run(r._read_frames())
    assert r._frame_count == 2
    assert r._last_pi == "F202"


def test_status_running_only_when_both_procs_alive_and_not_done():
    r = RdsRunner()
    # No procs yet → not running.
    assert r.status().running is False
    # Set both procs but mark _done → not running.
    r._rtl_proc = object()
    r._redsea_proc = object()
    r._done = True
    assert r.status().running is False
    # Reset _done → running.
    r._done = False
    # status() reads pid via redsea_proc.pid — patch a numeric pid attr.
    r._redsea_proc = type("P", (), {"pid": 42})()
    assert r.status().running is True
    assert r.status().pid == 42
