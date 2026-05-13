# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SO_PEERCRED-based authentication for the eye-square helper Unix socket.

The helper listens on /run/secubox/eye-square-helper.sock. Only specific UIDs
are allowed to call it (the dashboard user `secubox` and the right-panel user
`secubox-eye-square`, plus root for admin). Peer credentials are read from the
connected socket via SO_PEERCRED.
"""
from __future__ import annotations

import pwd
import socket
import struct

_ALLOWED_USERS = ("secubox", "secubox-eye-square", "root")


def _resolve_uid_by_name(name: str) -> int | None:
    """Resolve a username to its UID, or None if the user does not exist."""
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _build_allowed_uids() -> frozenset[int]:
    """Build the set of UIDs allowed to talk to the helper at module import."""
    uids: set[int] = set()
    for name in _ALLOWED_USERS:
        uid = _resolve_uid_by_name(name)
        if uid is not None:
            uids.add(uid)
    return frozenset(uids)


ALLOWED_UIDS: frozenset[int] = _build_allowed_uids()


def get_peer_uid(sock: socket.socket) -> int:
    """Return the UID of the peer on a connected AF_UNIX SOCK_STREAM socket.

    Uses SO_PEERCRED to read the (pid, uid, gid) tuple. Linux-specific.
    """
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", creds)
    return uid
