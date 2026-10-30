# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.wsserver — per-session WebSocket data-plane.

Binds the wg-mesh interface IP ONLY (never 0.0.0.0). Authenticates the center
with the single-use session token (hash matched against the journal's
AssistSession). Executes NO action any more (#3126 L2): the old catalog is gone and support
runs through the pilotage; console escalation is handled by the console module.
Every action is audited. Fail-closed: no wg-mesh ⇒ BindError ⇒ the daemon
does not serve.
"""
from __future__ import annotations

import fcntl
import socket
import struct
from typing import Optional

from . import audit
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


REMPLACE_PAR = "/api/v1/pilotage/boxes/<nom>/support"


async def dispatch(session: dict, action: str, arg: Optional[str], entries,
                   self_did: str, now_ts: str) -> dict:
    """Plus aucune action (#3126 L2, R-L2-4) : l'ancien catalogue est retiré, les
    actions passent par le ctl fermé `secubox-pilotagectl` dans une session de
    support du pilotage. Le refus est audité ; rien n'est exécuté."""
    audit.record("action.reject", session["session_id"], session.get("center_did", "?"),
                 {"action": action, "why": "catalogue-retire"})
    return {"ok": False, "gone": True, "remplace_par": REMPLACE_PAR,
            "error": "catalogue d'actions d'assistance retiré : utiliser le support du pilotage"}
