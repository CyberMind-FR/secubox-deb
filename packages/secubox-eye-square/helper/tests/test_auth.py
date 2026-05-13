# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for eye_square_helper.auth — SO_PEERCRED-based UID check."""
from __future__ import annotations

import os
import socket

import pytest

from eye_square_helper.auth import get_peer_uid, _resolve_uid_by_name


def test_get_peer_uid_returns_calling_uid(tmp_path):
    """Calling the helper from the same process must return os.getuid()."""
    sock_path = tmp_path / "test.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(sock_path))
    conn, _ = server.accept()

    try:
        uid = get_peer_uid(conn)
        assert uid == os.getuid()
    finally:
        conn.close()
        client.close()
        server.close()


def test_resolve_uid_by_name_root_is_zero():
    assert _resolve_uid_by_name("root") == 0


def test_resolve_uid_by_name_unknown_returns_none():
    assert _resolve_uid_by_name("nonexistent-user-xyz-12345") is None
