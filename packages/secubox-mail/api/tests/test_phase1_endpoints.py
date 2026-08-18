# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Phase 1 rev. 2 acceptance: every existing API endpoint still responds non-5xx
after the source-catch-up renames.

We don't care about response *content* here — only that the route is
registered and the handler doesn't 500 on a default invocation. JWT-protected
endpoints return 401 without a token; that still counts as "registered".
Phase 2+ tightens this to assert specific shapes.
"""
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).parents[2]))
from api.main import app  # noqa: E402

client = TestClient(app)

# Pulled from packages/secubox-mail/api/main.py via grep '@app\.' on 2026-05-15.
# 62 endpoints — keep this list in sync if main.py adds/removes routes.
LEGACY_ROUTES = [
    ("GET", "/status"),
    ("GET", "/health"),
    ("GET", "/components"),
    ("GET", "/access"),
    ("GET", "/mail/config-v1.1.xml"),
    ("GET", "/autoconfig/mail/config-v1.1.xml"),
    ("GET", "/autodiscover/autodiscover.xml"),
    ("POST", "/autodiscover/autodiscover.xml"),
    ("POST", "/Autodiscover/Autodiscover.xml"),
    ("GET", "/.well-known/autoconfig/mail/config-v1.1.xml"),
    ("GET", "/users"),
    ("POST", "/user"),
    ("DELETE", "/user/foo@example.com"),
    ("POST", "/user/password"),
    ("GET", "/aliases"),
    ("POST", "/alias"),
    ("DELETE", "/alias/foo@example.com"),
    ("POST", "/start"),
    ("POST", "/stop"),
    ("POST", "/restart"),
    ("POST", "/install"),
    ("GET", "/webmail/status"),
    ("POST", "/webmail/start"),
    ("POST", "/webmail/stop"),
    ("POST", "/webmail/restart"),
    ("POST", "/webmail/install"),
    ("POST", "/migrate"),
    ("GET", "/backups"),
    ("POST", "/backup"),
    ("POST", "/restore/test"),
    ("GET", "/logs"),
    ("GET", "/ssl"),
    ("POST", "/ssl/setup"),
    ("GET", "/acme/status"),
    ("POST", "/acme/issue"),
    ("POST", "/acme/renew"),
    ("POST", "/acme/install"),
    ("GET", "/dns-setup"),
    ("POST", "/user/repair/foo@example.com"),
    ("POST", "/fix-ports"),
    ("GET", "/settings"),
    ("POST", "/settings"),
    ("GET", "/dkim/status"),
    ("POST", "/dkim/setup"),
    ("POST", "/dkim/keygen"),
    ("POST", "/dkim/sync"),
    ("GET", "/dkim/record"),
    ("GET", "/spam/status"),
    ("POST", "/spam/setup"),
    ("POST", "/spam/enable"),
    ("POST", "/spam/disable"),
    ("POST", "/spam/update"),
    ("GET", "/grey/status"),
    ("POST", "/grey/setup"),
    ("POST", "/grey/enable"),
    ("POST", "/grey/disable"),
    ("GET", "/av/status"),
    ("POST", "/av/setup"),
    ("POST", "/av/enable"),
    ("POST", "/av/disable"),
    ("POST", "/av/update"),
    ("GET", "/example.com.mobileconfig"),
]


@pytest.mark.parametrize("method,path", LEGACY_ROUTES)
def test_route_responds(method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code < 500, (
        f"{method} {path} → {resp.status_code}: {resp.text[:200]}"
    )
