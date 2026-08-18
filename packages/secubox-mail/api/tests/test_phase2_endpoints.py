# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Phase 2: /rspamd/* new endpoints + legacy deprecation shims."""
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).parents[2]))
from api.main import app  # noqa: E402

client = TestClient(app)

NEW_ROUTES: list[tuple[str, str]] = []
LEGACY_SHIMS: list[tuple[str, str]] = []


@pytest.mark.parametrize("method,path", NEW_ROUTES)
def test_new_route_responds(method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code < 500, f"{method} {path} → {resp.status_code}"


@pytest.mark.parametrize("method,path", LEGACY_SHIMS)
def test_legacy_shim_has_deprecation_header(method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code < 500, f"{method} {path} → {resp.status_code}"
    assert resp.headers.get("x-deprecated-endpoint") == "rspamd", \
        f"{method} {path} missing deprecation header"
