# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ToolBoX — pont vers les routes /c2/* du démon sentinelle
CyberMind — https://cybermind.fr

fetch_c2 / c2_allow avaient disparu à la fusion du 2026-08-17 (#1778) : la
vue « C2 appris » restait vide et « Ignorer » ne faisait rien. Un vrai petit
serveur HTTP joue le démon, pour vérifier ce qui part réellement sur le fil.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest

from secubox_toolbox import sentinel_link as sl


@pytest.fixture()
def daemon(monkeypatch):
    seen = {"allow": []}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/c2/learned":
                self._json([{"host": "l.example", "signals": ["dga"]}])
            elif self.path == "/c2/candidates":
                self._json([{"host": "c.example", "signals": {"dga": True}}])
            else:
                self._json({}, 404)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode()
            if self.path == "/c2/allow":
                seen["allow"].append((self.headers.get("Content-Type"), parse_qs(body)))
                self._json({"ok": True})
            else:
                self._json({}, 404)

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setattr(sl, "daemon_base", lambda: f"http://127.0.0.1:{srv.server_port}")
    yield seen
    srv.shutdown()


def test_fetch_c2_reads_both_views(daemon):
    d = sl.fetch_c2()
    assert d["learned"][0]["host"] == "l.example"
    assert d["candidates"][0]["host"] == "c.example"


def test_c2_allow_posts_form_encoded_host(daemon):
    assert sl.c2_allow("fp.example") is True
    ctype, form = daemon["allow"][0]
    assert ctype == "application/x-www-form-urlencoded"
    assert form == {"host": ["fp.example"]}


def test_c2_allow_empty_host_never_posts(daemon):
    assert sl.c2_allow("") is False
    assert daemon["allow"] == []


def test_c2_failsafe_when_daemon_down(monkeypatch):
    monkeypatch.setattr(sl, "daemon_base", lambda: "http://127.0.0.1:9")
    assert sl.fetch_c2() == {}
    assert sl.c2_allow("x.example") is False
    monkeypatch.setattr(sl, "daemon_base", lambda: None)
    assert sl.fetch_c2() == {}
    assert sl.c2_allow("x.example") is False
