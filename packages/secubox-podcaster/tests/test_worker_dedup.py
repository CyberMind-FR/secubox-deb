# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: podcaster download-worker dedup/cancel tests
CyberMind — https://cybermind.fr

Guards the #853 concurrency fix: the worker must never run two _download_one
for the same episode (they share deterministic tmp/dest paths → corruption),
and a manual restart must be able to cancel a live download and start a fresh
one.
"""
import asyncio
import logging
import sys
import types

import pytest


@pytest.fixture
def main(monkeypatch):
    # Stub secubox_core so api.main imports without the real package installed.
    from fastapi import APIRouter
    core = types.ModuleType("secubox_core")
    auth = types.ModuleType("secubox_core.auth")
    logm = types.ModuleType("secubox_core.logger")
    auth.router = APIRouter()
    auth.require_jwt = lambda: None
    logm.get_logger = lambda n: logging.getLogger(n)
    monkeypatch.setitem(sys.modules, "secubox_core", core)
    monkeypatch.setitem(sys.modules, "secubox_core.auth", auth)
    monkeypatch.setitem(sys.modules, "secubox_core.logger", logm)
    import api.main as m
    return m


def test_worker_dedups_and_supports_cancel_restart(main):
    m = main

    async def scenario():
        calls = []

        async def fake_dl(ep_id):
            calls.append(("start", ep_id))
            try:
                await asyncio.sleep(0.3)
            except asyncio.CancelledError:
                calls.append(("cancel", ep_id))
                raise
            calls.append(("done", ep_id))

        m._download_one = fake_dl
        m._inflight.clear()
        m._queue = asyncio.Queue()
        worker = asyncio.create_task(m._worker())
        try:
            # Two puts for the same in-flight episode → exactly one download.
            await m._queue.put(1)
            await m._queue.put(1)
            await asyncio.sleep(0.1)
            assert calls.count(("start", 1)) == 1, calls

            # Manual restart cancels the live task, then a re-put starts fresh.
            t = m._inflight.get(1)
            t.cancel()
            try:
                await t
            except BaseException:
                pass
            await m._queue.put(1)
            await asyncio.sleep(0.1)
            assert ("cancel", 1) in calls, calls
            assert calls.count(("start", 1)) == 2, calls
        finally:
            worker.cancel()

    asyncio.run(scenario())
