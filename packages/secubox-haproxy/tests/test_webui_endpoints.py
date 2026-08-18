# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: webui endpoints tests
"""
import textwrap
import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from api import webui_identity as wi


@pytest.fixture
def client(tmp_path, monkeypatch):
    p = tmp_path / "secubox"
    p.write_text(textwrap.dedent("""\
        SECUBOX_HOSTNAME="gk2"
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """))
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    wi.invalidate_cache()
    return TestClient(api_main.app)


def test_admin_domain_returns_canonical_identity(client):
    r = client.get("/webui/admin-domain")
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "hostname": "gk2",
        "domain_suffix": "secubox.in",
        "admin_domain": "admin.gk2.secubox.in",
        "regex": r"^admin\.gk2\.secubox\.in$",
    }


def test_admin_domain_503_when_unset(client, tmp_path, monkeypatch):
    p = tmp_path / "secubox-empty"
    p.write_text("")
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    wi.invalidate_cache()
    r = client.get("/webui/admin-domain")
    assert r.status_code == 503
    assert "SECUBOX_HOSTNAME" in r.json()["detail"]


def test_nginx_config_is_public(client):
    """Endpoint is intentionally public — content is derivable from /webui/admin-domain
    and the unix socket is root-only at the filesystem level."""
    r = client.get("/webui/nginx-config")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")


def test_nginx_config_returns_rendered_vhost(client):
    r = client.get("/webui/nginx-config")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert r"server_name ~^admin\.gk2\.secubox\.in$;" in body
    assert "listen 0.0.0.0:9080;" in body
    assert "root /usr/share/secubox/www;" in body
    assert "include /etc/nginx/secubox.d/*.conf;" in body


def test_generate_includes_strict_webui_acl(client, tmp_path, monkeypatch):
    """When /generate runs with a configured HOSTNAME, it emits the strict ACL + webui_direct backend."""
    import api.main as _mn
    from api.main import app
    from secubox_core.auth import require_jwt

    # Redirect HAProxy cfg writes to a temp file so we don't need root
    cfg_tmp = tmp_path / "haproxy.cfg"
    monkeypatch.setattr(_mn, "HAPROXY_CFG", str(cfg_tmp))

    # Stub out haproxy validation and WAF sync so /generate completes
    import subprocess
    import unittest.mock as mock

    fake_result = mock.MagicMock()
    fake_result.returncode = 0
    fake_result.stderr = ""
    fake_result.stdout = "Configuration file is valid\n"

    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        with mock.patch("subprocess.run", return_value=fake_result), \
             mock.patch.object(_mn, "sync_waf_routes", return_value=None):
            r = client.post("/generate")
    finally:
        app.dependency_overrides.clear()

    assert r.status_code == 200, f"Unexpected status {r.status_code}: {r.text}"

    # /generate writes the rendered config to HAPROXY_CFG — read it back
    text = cfg_tmp.read_text()
    assert r"acl is_webui_admin hdr(host) -m reg ^admin\.gk2\.secubox\.in$" in text, \
        f"Strict ACL not found in generated config:\n{text}"
    assert "use_backend webui_direct if is_webui_admin" in text, \
        f"use_backend webui_direct directive missing:\n{text}"
    assert "backend webui_direct" in text, \
        f"backend webui_direct definition missing:\n{text}"
    # Verify the ACL appears twice — once in http-in, once in https-in
    assert text.count("acl is_webui_admin") == 2, \
        f"Expected 2 occurrences of 'acl is_webui_admin', got {text.count('acl is_webui_admin')}"


def test_refresh_invalidates_cache(client, tmp_path, monkeypatch):
    from api.main import app
    from secubox_core.auth import require_jwt
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        # First call seeds the cache via /admin-domain
        r1 = client.get("/webui/admin-domain")
        assert r1.json()["hostname"] == "gk2"
        # Mutate the file under the API's feet
        wi.DEFAULTS_FILE.write_text('SECUBOX_HOSTNAME="changed"\n')
        # Without refresh, the API still sees old value
        r2 = client.get("/webui/admin-domain")
        assert r2.json()["hostname"] == "gk2"
        # Refresh
        r3 = client.post("/webui/refresh")
        assert r3.status_code == 204
        # Now the API sees the new value
        r4 = client.get("/webui/admin-domain")
        assert r4.json()["hostname"] == "changed"
    finally:
        app.dependency_overrides.clear()
