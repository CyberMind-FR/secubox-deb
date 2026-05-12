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
