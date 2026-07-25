# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from assist import diag


def test_redacts_token_and_password():
    s = 'token = "abcdef123456" password=hunter2 API_KEY: zzz'
    out = diag.redact(s)
    assert "abcdef123456" not in out
    assert "hunter2" not in out
    assert "zzz" not in out
    assert "***" in out


def test_redacts_long_hex_secret():
    s = "key " + "a" * 64
    assert "a" * 64 not in diag.redact(s)


def test_collect_has_no_secret_paths(monkeypatch):
    b = diag.collect(now_ts="2026-07-25T12:00:00Z")
    assert "generated_at" in b and "modules" in b and "logs" in b
    blob = repr(b).lower()
    assert "/etc/secubox/secrets" not in blob
    assert ".key" not in blob
