# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Nextcloud — _public_base_url unit tests

Regression guard: /connections must never hand a client localhost when a
real public domain is configured (clients reach Nextcloud through HAProxy
TLS 1.3). The helper is pure so it is tested without importing the FastAPI
app (which starts a cache thread + LXC probes at import time).
"""

import ast
import textwrap
from pathlib import Path

MAIN = Path(__file__).resolve().parent.parent / "api" / "main.py"


def _load_helper():
    """Extract and exec only the _public_base_url function from api/main.py."""
    tree = ast.parse(MAIN.read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_public_base_url":
            src = textwrap.dedent(ast.get_source_segment(MAIN.read_text(), node))
            ns: dict = {}
            exec(src, ns)
            return ns["_public_base_url"]
    raise AssertionError("_public_base_url not found in api/main.py")


_public_base_url = _load_helper()


def test_configured_domain_yields_https_not_localhost():
    # The bug: secubox.conf [nextcloud] has domain but no ssl_domain.
    assert _public_base_url("", "nc.gk2.secubox.in", 8080) == "https://nc.gk2.secubox.in"


def test_ssl_domain_takes_precedence():
    assert _public_base_url("secure.example.com", "nc.gk2.secubox.in", 8080) == \
        "https://secure.example.com"


def test_placeholder_domain_falls_back_to_localhost():
    assert _public_base_url("", "cloud.local", 8080) == "http://localhost:8080"


def test_bare_host_without_dot_falls_back_to_localhost():
    assert _public_base_url("", "nextcloud", 9000) == "http://localhost:9000"
