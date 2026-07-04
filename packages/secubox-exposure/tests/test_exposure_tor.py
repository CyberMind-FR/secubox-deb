# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.api tests — _apply_tor thread-offload wiring (ref #793).

_apply_tor is invoked from set_exposure on the shared in-process aggregator
event loop. tor_add's blocking sleep/poll (up to 10s) must never run inline on
that loop (board-wide SPOF) — it must go through asyncio.to_thread. These
tests assert the add/remove decision logic and the offload, without touching
real torrc/systemctl.
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-exposure"))

import api.main as m


def test_tor_add_endpoint_refuses_excluded_host(tmp_path, monkeypatch):
    """The cert-pin gate must cover the direct /tor/add path (and /emancipate,
    which routes through it), not only POST /exposure — else it is bypassable."""
    import pytest
    from fastapi import HTTPException
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m._excl, "exclusion_reason",
                        lambda h: (True, "MITM-bypass (cert-pinned): test") if "signal" in h else (False, ""))
    called = []
    monkeypatch.setattr(m, "_tor_add_sync",
                        lambda name, local_port, onion_port: called.append(name) or {"success": True})

    with pytest.raises(HTTPException) as ei:
        asyncio.run(m.tor_add(m.TorAddRequest(service="signal.org", local_port=80), {"sub": "admin"}))
    assert ei.value.status_code == 400
    assert called == []                                    # never created the hidden service

    asyncio.run(m.tor_add(m.TorAddRequest(service="myblog", local_port=80), {"sub": "admin"}))
    assert called == ["myblog"]                            # non-excluded proceeds


def test_apply_tor_add_calls_sync_helper_when_hs_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    calls = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: calls.append((name, local_port, onion_port)))
    monkeypatch.setattr(m, "_tor_remove_sync", lambda name: calls.append(("remove", name)))

    # dots are stripped by the existing sanitization (isalnum or _/-), same as tor_add
    asyncio.run(m._apply_tor("z-example", True, {"sub": "admin"}))

    assert calls == [("z-example", 80, 80)]


def test_apply_tor_remove_calls_sync_helper_when_hs_present(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    (tmp_path / "z-example").mkdir()
    calls = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: calls.append(("add", name)))
    monkeypatch.setattr(m, "_tor_remove_sync", lambda name: calls.append(("remove", name)))

    asyncio.run(m._apply_tor("z-example", False, {"sub": "admin"}))

    assert calls == [("remove", "z-example")]


def test_apply_tor_add_noop_when_hs_already_present(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    (tmp_path / "z-example").mkdir()
    calls = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: calls.append(("add", name)))
    monkeypatch.setattr(m, "_tor_remove_sync", lambda name: calls.append(("remove", name)))

    asyncio.run(m._apply_tor("z-example", True, {"sub": "admin"}))

    assert calls == []


def test_apply_tor_remove_noop_when_hs_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    calls = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: calls.append(("add", name)))
    monkeypatch.setattr(m, "_tor_remove_sync", lambda name: calls.append(("remove", name)))

    asyncio.run(m._apply_tor("z-example", False, {"sub": "admin"}))

    assert calls == []


def test_apply_tor_swallows_exceptions(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)

    def _boom(name, local_port, onion_port):
        raise RuntimeError("torrc write failed")
    monkeypatch.setattr(m, "_tor_add_sync", _boom)

    # must not raise — a Tor hiccup must not fail the reach change
    asyncio.run(m._apply_tor("z.example", True, {"sub": "admin"}))


def test_apply_tor_sanitizes_vhost_name(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    calls = []
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: calls.append(name))

    asyncio.run(m._apply_tor("weird!name/../x", True, {"sub": "admin"}))

    # only alnum/_/- survive, matching the existing tor_add sanitization
    assert calls == ["weirdnamex"]


def test_apply_tor_offloads_to_a_thread(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "TOR_DATA", tmp_path)
    monkeypatch.setattr(m, "_tor_add_sync", lambda name, local_port, onion_port: None)

    recorded = {}
    real_to_thread = asyncio.to_thread

    async def _spy_to_thread(func, *args, **kwargs):
        recorded["called"] = True
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(m.asyncio, "to_thread", _spy_to_thread)

    asyncio.run(m._apply_tor("z.example", True, {"sub": "admin"}))

    assert recorded.get("called") is True
