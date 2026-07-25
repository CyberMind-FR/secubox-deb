# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: assist.daemon — WebSocket serve loop over wg-mesh."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

import websockets

sys.path.insert(0, os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))
from annuaire.log import Journal  # noqa: E402
from assist import wsserver  # noqa: E402

WS_PORT = int(os.environ.get("SECUBOX_ASSIST_WS_PORT", "8099"))


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _journal_path():
    return os.environ.get("ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")


def _self_did():
    from annuaire.crypto import public_from_private, did_from_pubkey
    raw = bytes.fromhex(open(os.environ.get(
        "ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")).read().strip())
    return did_from_pubkey(public_from_private(raw))


def _read_entries():
    return list(Journal(_journal_path()).iter_entries())


def _dispatch_blocking(session, action, arg, entries, self_did, now_ts):
    """Run wsserver.dispatch (sync subprocess.run under an `async def`
    signature we must not change) to completion on its own event loop, so
    asyncio.to_thread can offload it to a worker thread."""
    return asyncio.run(wsserver.dispatch(session, action, arg, entries, self_did, now_ts))


async def handler(ws):
    entries = await asyncio.to_thread(_read_entries)
    self_did = _self_did()
    tok = await ws.recv()
    try:
        session = await wsserver.authorize(tok, entries, self_did, _now())
    except wsserver.AuthError as exc:
        await ws.send(json.dumps({"ok": False, "error": str(exc)})); return
    await ws.send(json.dumps({"ok": True, "session_id": session["session_id"]}))
    async for msg in ws:
        req = json.loads(msg)
        fresh = await asyncio.to_thread(_read_entries)
        # re-check session still active every action (revoke/expiry fail-closed)
        if wsserver._assist.active_session(fresh, self_did, _now()) is None:
            await ws.send(json.dumps({"ok": False, "error": "session-ended"})); break
        # wsserver.dispatch does sync subprocess.run (up to 60s) and
        # diag.collect chains many sequential sync subprocess calls — off the
        # single asyncio loop via to_thread so one session can't stall every
        # other connection (the podcaster/peertube loop-block bug class).
        out = await asyncio.to_thread(_dispatch_blocking, session, req.get("action"),
                                      req.get("arg"), fresh, self_did, _now())
        await ws.send(json.dumps(out))


async def _main():
    ip = wsserver.mesh_bind_ip("wg-mesh")  # BindError → crash (fail-closed) if no mesh
    async with websockets.serve(handler, ip, WS_PORT):
        await asyncio.Future()


def main():
    asyncio.run(_main())


if __name__ == "__main__":
    main()
