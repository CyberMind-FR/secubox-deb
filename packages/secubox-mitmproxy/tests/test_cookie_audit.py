# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import hashlib
import json
from types import SimpleNamespace

import pytest

from cookie_audit import CookieAudit, parse_set_cookie


def test_parse_set_cookie_full_attrs():
    raw = "sid=abc123; Domain=example.com; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
    p = parse_set_cookie(raw)
    assert p["name"] == "sid"
    assert p["value_hash"] == hashlib.sha256(b"abc123").hexdigest()
    assert p["domain"] == "example.com"
    assert p["path"] == "/"
    assert p["max_age"] == 3600
    assert p["secure"] is True
    assert p["httponly"] is True
    assert p["samesite"] == "Lax"


def test_parse_set_cookie_minimal():
    p = parse_set_cookie("foo=bar")
    assert p["name"] == "foo"
    assert p["value_hash"] == hashlib.sha256(b"bar").hexdigest()
    assert p["secure"] is False
    assert p["httponly"] is False
    assert p["samesite"] is None


def test_parse_set_cookie_empty_value():
    p = parse_set_cookie("tracker=")
    assert p["name"] == "tracker"
    assert p["value_hash"] == hashlib.sha256(b"").hexdigest()


def test_parse_set_cookie_garbage():
    assert parse_set_cookie("") == {}
    assert parse_set_cookie("no_equals_sign") == {}


def _flow(host, path, set_cookies, referer=""):
    class _Headers:
        def __init__(self, items):
            self._items = list(items)

        def get_all(self, key):
            return [v for k, v in self._items if k.lower() == key.lower()]

        def get(self, key, default=None):
            for k, v in self._items:
                if k.lower() == key.lower():
                    return v
            return default

    req_headers = _Headers([("Referer", referer)] if referer else [])
    req = SimpleNamespace(host=host, path=path, headers=req_headers,
                          pretty_url=f"https://{host}{path}")
    resp_headers = _Headers([("Set-Cookie", sc) for sc in set_cookies])
    resp = SimpleNamespace(headers=resp_headers, status_code=200)
    return SimpleNamespace(request=req, response=resp)


def test_addon_appends_jsonl(tmp_path):
    ledger = tmp_path / "server.jsonl"
    addon = CookieAudit(ledger_path=str(ledger))
    flow = _flow("foo.example.com", "/", [
        "sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
        "lang=fr; Path=/",
    ])
    addon.response(flow)
    lines = ledger.read_text().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["vhost"] == "foo.example.com"
    assert rec["name"] == "sid"
    assert rec["httponly"] is True
    assert rec["samesite"] == "Strict"
    assert "ts" in rec
    assert rec["value_hash"] == hashlib.sha256(b"abc").hexdigest()


def test_addon_skips_when_no_set_cookie(tmp_path):
    ledger = tmp_path / "server.jsonl"
    addon = CookieAudit(ledger_path=str(ledger))
    flow = _flow("foo.example.com", "/", [])
    addon.response(flow)
    assert (not ledger.exists()) or ledger.read_text() == ""


def test_addon_handles_none_response(tmp_path):
    ledger = tmp_path / "server.jsonl"
    addon = CookieAudit(ledger_path=str(ledger))
    flow = SimpleNamespace(request=SimpleNamespace(host="x", path="/", headers={}),
                           response=None)
    addon.response(flow)
    assert (not ledger.exists()) or ledger.read_text() == ""
