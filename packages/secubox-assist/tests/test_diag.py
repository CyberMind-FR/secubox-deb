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


def test_redacts_bearer_token_with_colon_separator():
    s = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.pay.sig"
    out = diag.redact(s)
    assert "eyJhbGciOiJIUzI1NiJ9.pay.sig" not in out
    assert "***" in out


def test_redacts_standalone_bearer_keyword_space_separator():
    s = "Bearer eyJhbGciOiJIUzI1NiJ9.pay.sig"
    out = diag.redact(s)
    assert "eyJhbGciOiJIUzI1NiJ9.pay.sig" not in out
    assert "***" in out


def test_redacts_basic_auth_credential():
    s = "authorization: Basic dXNlcjpwYXNz"
    out = diag.redact(s)
    assert "dXNlcjpwYXNz" not in out
    assert "***" in out


def test_redacts_json_quoted_password():
    s = '{"password": "s3cr3tVal"}'
    out = diag.redact(s)
    assert "s3cr3tVal" not in out
    assert "***" in out


def test_redacts_json_quoted_api_key():
    s = '{"api_key":"zzz2"}'
    out = diag.redact(s)
    assert "zzz2" not in out
    assert "***" in out


def test_redacts_email_local_part():
    s = "contact alice@example.com for details"
    out = diag.redact(s)
    assert "alice@example.com" not in out
    assert "***@example.com" in out


def test_redacts_access_token_compound_field():
    s = '{"access_token": "eyJsecretjwt.payload.sig"}'
    out = diag.redact(s)
    assert "eyJsecretjwt.payload.sig" not in out
    assert "***" in out


def test_redacts_refresh_token_compound_field():
    s = '{"refresh_token":"rt-xxxxxxxxxxxxxxxxxxxx"}'
    out = diag.redact(s)
    assert "rt-xxxxxxxxxxxxxxxxxxxx" not in out
    assert "***" in out


def test_redacts_client_secret_compound_field():
    s = '{"client_secret": "supersecretvalue123"}'
    out = diag.redact(s)
    assert "supersecretvalue123" not in out
    assert "***" in out


def test_redacts_generic_underscore_prefixed_password():
    s = "my_password=hunter3"
    out = diag.redact(s)
    assert "hunter3" not in out
    assert "***" in out


def test_collect_has_no_secret_paths(monkeypatch):
    b = diag.collect(now_ts="2026-07-25T12:00:00Z")
    assert "generated_at" in b and "modules" in b and "logs" in b
    blob = repr(b).lower()
    assert "/etc/secubox/secrets" not in blob
    assert ".key" not in blob
