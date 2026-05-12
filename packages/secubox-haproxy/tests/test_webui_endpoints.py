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


def test_nginx_config_requires_jwt(client):
    r = client.get("/webui/nginx-config")
    assert r.status_code in (401, 403)


def test_nginx_config_returns_rendered_vhost(client, monkeypatch):
    # Bypass JWT for this test by overriding the dependency
    from api.main import app
    from secubox_core.auth import require_jwt
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        r = client.get("/webui/nginx-config")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert r"server_name ~^admin\.gk2\.secubox\.in$;" in body
    assert "listen 0.0.0.0:9080;" in body
    assert "root /usr/share/secubox/www;" in body
    assert "include /etc/nginx/secubox.d/*.conf;" in body


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
