# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.wsserver — per-session WebSocket data-plane.

Binds the wg-mesh interface IP ONLY (never 0.0.0.0). Authenticates the center
with the single-use session token (hash matched against the journal's
AssistSession). Dispatches ONLY catalog actions; console escalation (a live
pty channel) is handled by the separate console module, not gated here.
Every action is audited. Fail-closed: no wg-mesh ⇒ BindError ⇒ the daemon
does not serve.
"""
from __future__ import annotations

import fcntl
import socket
import struct
import subprocess
from typing import Optional

from . import audit, diag
from .catalog import CatalogError, resolve
from .token import verify_token

try:  # annuaire is a runtime dependency (prod: /usr/lib/secubox/annuaire on path)
    from annuaire import assist as _assist
except Exception:  # pragma: no cover - import shim for isolated unit tests
    _assist = None


class BindError(Exception):
    """The wg-mesh interface is absent — refuse to serve (fail-closed)."""


class AuthError(Exception):
    """Presented token does not match any active session."""


def mesh_bind_ip(iface: str = "wg-mesh") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", iface[:15].encode("utf-8"))
        addr = fcntl.ioctl(s.fileno(), 0x8915, packed)  # SIOCGIFADDR
        return socket.inet_ntoa(addr[20:24])
    except OSError as exc:
        raise BindError(f"wg-mesh iface {iface!r} unavailable: {exc}") from exc
    finally:
        s.close()


async def authorize(tok: str, entries, self_did: str, now_ts: str) -> dict:
    """Return the active session matching tok, else AuthError."""
    if _assist is None:
        raise AuthError("annuaire.assist unavailable")
    try:
        session = _assist.active_session(entries, self_did, now_ts)
    except _assist.AssistError as exc:
        raise AuthError("multiple-active-sessions") from exc
    if session and verify_token(tok, session.get("token_hash", "")):
        return session
    raise AuthError("no active session for token")


async def dispatch(session: dict, action: str, arg: Optional[str], entries,
                   self_did: str, now_ts: str) -> dict:
    """Run one catalog action; console escalation is handled by the separate
    console module, not by this dispatcher."""
    sid = session["session_id"]
    center = session.get("center_did", "?")
    try:
        argv = resolve(action, arg)
    except CatalogError as exc:
        audit.record("action.reject", sid, center, {"action": action, "why": str(exc)})
        return {"ok": False, "error": str(exc)}
    audit.record("action.run", sid, center, {"action": action, "arg": arg})
    if action == "diag.collect":
        return {"ok": True, "output": diag.collect(now_ts)}
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return {"ok": r.returncode == 0, "output": r.stdout, "error": r.stderr}
    except Exception as exc:  # noqa: BLE001
        audit.record("action.error", sid, center, {"action": action, "err": str(exc)})
        return {"ok": False, "error": str(exc)}
