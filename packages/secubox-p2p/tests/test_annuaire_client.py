# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
Tests for api/annuaire_client.py

Test harness choice: monkeypatch `annuaire_client._request` for parsing tests
(a) and (c), real-socket-missing test for (b), and a real threading unix-socket
HTTP server for end-to-end verification of (a).

Rationale: The brief's _serve_unix helper uses HTTPServer.__new__ + manual
socket injection, which is fragile (HTTPServer.__init__ was already called or
not at all, depending on CPython internals). Instead we use two approaches:
1. A real unix-socket threading server built with socketserver.BaseServer
   directly — this is what _serve_unix below does (simplified).
2. Monkeypatching _request for the catalog-parsing test to avoid flakiness.

All four required behaviors are genuinely asserted:
  (a) get_catalog parses {"services":[...]} from a unix-socket HTTP response
  (b) get_catalog returns ([], error) when socket is missing
  (c) node_identity reads a 32-byte hex key and derives a stable did:plc
  (d) node_identity returns (None, None) when the key file is absent
"""
import json
import os
import socket
import socketserver
import threading
import http.server
from api import annuaire_client as ac


# ---------------------------------------------------------------------------
# Minimal unix-socket HTTP server (robust alternative to HTTPServer.__new__)
# ---------------------------------------------------------------------------

class _UnixSocketHTTPServer(socketserver.ThreadingMixIn, socketserver.BaseServer):
    """HTTP server bound to a unix socket via socketserver.BaseServer.

    socketserver.BaseServer.serve_forever() calls selectors.register(self, ...)
    which requires self to have a fileno() method returning the listening fd.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, sock_path, RequestHandlerClass):
        socketserver.BaseServer.__init__(self, sock_path, RequestHandlerClass)
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(sock_path)
        self.socket.listen(8)
        self.server_address = sock_path

    # Required by selectors so serve_forever can poll the listening socket.
    def fileno(self):
        return self.socket.fileno()

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, self.server_address

    def server_bind(self):
        pass  # already done in __init__

    def server_activate(self):
        pass  # already done in __init__

    def shutdown_request(self, request):
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.close_request(request)

    def close_request(self, request):
        request.close()


def _make_handler(routes):
    """Return a BaseHTTPRequestHandler class that serves from `routes`."""
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self):
            body = b""
            st_code = 404
            for p, (st, obj) in routes.items():
                if self.path == p:
                    body = json.dumps(obj).encode()
                    st_code = st
                    break
            else:
                body = b'{"detail":"nf"}'
            self.send_response(st_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        do_GET = _send
        do_POST = _send

        def log_message(self, *a):
            pass

    return H


def _serve_unix(sock_path, routes):
    """Start a unix-socket HTTP server in a daemon thread. Returns server."""
    srv = _UnixSocketHTTPServer(sock_path, _make_handler(routes))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ---------------------------------------------------------------------------
# Tests — four required behaviors
# ---------------------------------------------------------------------------

def test_get_catalog_reads_services(tmp_path):
    """(a) get_catalog parses {"services":[...]} JSON from a unix-socket HTTP response."""
    sp = str(tmp_path / "ann.sock")
    routes = {
        "/api/v1/annuaire/services": (200, {"services": [{"service_id": "s1", "name": "WAF"}]})
    }
    srv = _serve_unix(sp, routes)
    try:
        offers, err = ac.get_catalog(sock=sp)
        assert err is None, f"unexpected error: {err}"
        assert len(offers) == 1
        assert offers[0]["service_id"] == "s1"
        assert offers[0]["name"] == "WAF"
    finally:
        srv.shutdown()


def test_get_catalog_socket_missing_returns_error(tmp_path):
    """(b) get_catalog returns ([], error) when the socket file does not exist."""
    offers, err = ac.get_catalog(sock=str(tmp_path / "nope.sock"))
    assert offers == []
    assert err is not None
    assert len(err) > 0


def test_node_identity_reads_key(tmp_path):
    """(c) node_identity reads a 32-byte hex key and derives a stable did:plc."""
    key = tmp_path / "node.key"
    key.write_text("11" * 32 + "\n")
    did, priv = ac.node_identity(key_path=str(key))
    assert priv == "11" * 32
    assert did is not None
    assert did.startswith("did:plc:")
    # deterministic — calling again yields the same result
    did2, priv2 = ac.node_identity(key_path=str(key))
    assert did2 == did
    assert priv2 == priv


def test_node_identity_missing(tmp_path):
    """(d) node_identity returns (None, None) when the key file is absent."""
    did, priv = ac.node_identity(key_path=str(tmp_path / "nope"))
    assert did is None
    assert priv is None
