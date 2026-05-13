# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for IPCBridge — WS server in PySide6 process, receives Chromium events."""
from __future__ import annotations

import asyncio
import json

import pytest
import websockets

from secubox_eye_square_right_panel.ipc_bridge import IPCBridge


@pytest.mark.asyncio
async def test_ipc_bridge_receives_module_tap():
    bridge = IPCBridge(host="127.0.0.1", port=19090)
    received: list[str] = []
    bridge.on_module_tap = lambda mod: received.append(mod)

    server_task = asyncio.create_task(bridge.serve())
    await asyncio.sleep(0.1)

    async with websockets.connect("ws://127.0.0.1:19090/eye-square") as ws:
        await ws.send(json.dumps({"event": "module:tap", "module": "AUTH"}))
        await asyncio.sleep(0.1)

    bridge.stop()
    try:
        await asyncio.wait_for(server_task, timeout=2.0)
    except asyncio.TimeoutError:
        pass

    assert received == ["AUTH"]


@pytest.mark.asyncio
async def test_ipc_bridge_receives_transport_status():
    bridge = IPCBridge(host="127.0.0.1", port=19091)
    received: list[str] = []
    bridge.on_transport_change = lambda active: received.append(active)

    server_task = asyncio.create_task(bridge.serve())
    await asyncio.sleep(0.1)

    async with websockets.connect("ws://127.0.0.1:19091/eye-square") as ws:
        await ws.send(json.dumps({"event": "transport:status", "active": "WiFi"}))
        await asyncio.sleep(0.1)

    bridge.stop()
    try:
        await asyncio.wait_for(server_task, timeout=2.0)
    except asyncio.TimeoutError:
        pass

    assert received == ["WiFi"]


@pytest.mark.asyncio
async def test_ipc_bridge_ignores_unknown_event():
    bridge = IPCBridge(host="127.0.0.1", port=19092)
    received: list[str] = []
    bridge.on_module_tap = lambda mod: received.append(mod)
    bridge.on_transport_change = lambda a: received.append(a)

    server_task = asyncio.create_task(bridge.serve())
    await asyncio.sleep(0.1)

    async with websockets.connect("ws://127.0.0.1:19092/eye-square") as ws:
        await ws.send(json.dumps({"event": "unknown:event", "data": "x"}))
        await asyncio.sleep(0.1)

    bridge.stop()
    try:
        await asyncio.wait_for(server_task, timeout=2.0)
    except asyncio.TimeoutError:
        pass

    assert received == []


@pytest.mark.asyncio
async def test_ipc_bridge_ignores_non_json():
    bridge = IPCBridge(host="127.0.0.1", port=19093)
    received: list[str] = []
    bridge.on_module_tap = lambda mod: received.append(mod)

    server_task = asyncio.create_task(bridge.serve())
    await asyncio.sleep(0.1)

    async with websockets.connect("ws://127.0.0.1:19093/eye-square") as ws:
        await ws.send("not-json-at-all")
        await asyncio.sleep(0.1)

    bridge.stop()
    try:
        await asyncio.wait_for(server_task, timeout=2.0)
    except asyncio.TimeoutError:
        pass

    assert received == []
