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


def _resolve_self_did():
    """Resolve this box's own DID from a PUBLIC source only.

    A network-facing daemon must never hold/read the sovereign PRIVATE key
    (that file is 0600 secubox:secubox — secubox-assist has no business
    opening it, and doing so was the previous bug: PermissionError on every
    connection). Order: explicit env var, then the world-readable DID file
    the postinst derives once from the key at package-install time. If
    neither is present, return None — authorize() then denies every session
    (fail-closed) rather than silently trusting an unresolved identity.
    """
    env = os.environ.get("SECUBOX_SELF_DID")
    if env:
        return env
    path = os.environ.get("ANNUAIRE_DID_PATH", "/etc/secubox/annuaire/node.did")
    try:
        with open(path) as f:
            v = f.read().strip()
            return v or None
    except OSError:
        return None


# Cached ONCE at module load — never re-derived per-connection.
SELF_DID = _resolve_self_did()


def _read_entries():
    return list(Journal(_journal_path()).iter_entries())


def _dispatch_blocking(session, action, arg, entries, self_did, now_ts):
    """Run wsserver.dispatch (sync subprocess.run under an `async def`
    signature we must not change) to completion on its own event loop, so
    asyncio.to_thread can offload it to a worker thread."""
    return asyncio.run(wsserver.dispatch(session, action, arg, entries, self_did, now_ts))


async def handler(ws):
    entries = await asyncio.to_thread(_read_entries)
    tok = await ws.recv()
    try:
        session = await wsserver.authorize(tok, entries, SELF_DID, _now())
    except wsserver.AuthError as exc:
        await ws.send(json.dumps({"ok": False, "error": str(exc)})); return
    await ws.send(json.dumps({"ok": True, "session_id": session["session_id"]}))
    async for msg in ws:
        req = json.loads(msg)
        fresh = await asyncio.to_thread(_read_entries)
        # Re-check every action against the SAME session_id this socket
        # authorized — not merely "some session is active". If the operator
        # closed this session and opened a different one (s2) in the
        # meantime, active_session() below returns s2 (non-None), but this
        # socket must still be cut off: it was never authorized for s2.
        active = wsserver._assist.active_session(fresh, SELF_DID, _now())
        if active is None or active.get("session_id") != session["session_id"]:
            await ws.send(json.dumps({"ok": False, "error": "session-ended"})); break
        # wsserver.dispatch does sync subprocess.run (up to 60s) and
        # diag.collect chains many sequential sync subprocess calls — off the
        # single asyncio loop via to_thread so one session can't stall every
        # other connection (the podcaster/peertube loop-block bug class).
        out = await asyncio.to_thread(_dispatch_blocking, session, req.get("action"),
                                      req.get("arg"), fresh, SELF_DID, _now())
        await ws.send(json.dumps(out))


async def _main():
    ip = wsserver.mesh_bind_ip("wg-mesh")  # BindError → crash (fail-closed) if no mesh
    async with websockets.serve(handler, ip, WS_PORT):
        await asyncio.Future()


def main():
    asyncio.run(_main())


if __name__ == "__main__":
    main()
