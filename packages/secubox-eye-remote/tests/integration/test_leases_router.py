# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote leases router integration tests."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch, tmp_path: Path) -> TestClient:
    leases = tmp_path / "leases"
    leases.write_text(
        "4000000000 02:fb:00:00:11:03 10.55.0.11 eye-rpiz id1\n"
        "4000003600 02:fb:00:00:d2:7f 10.55.0.12 eye-pi4b id2\n"
    )
    res = tmp_path / "reservations.conf"
    res.write_text(
        "dhcp-host=02:fb:00:00:11:03,10.55.0.11,eye-rpiz,24h\n"
        "dhcp-host=02:fb:00:00:d2:7f,10.55.0.12,eye-pi4b,24h\n"
    )
    monkeypatch.setenv("SECUBOX_EYE_LEASE_FILE", str(leases))
    monkeypatch.setenv("SECUBOX_EYE_RESERVATIONS_FILE", str(res))

    from api.main import app

    return TestClient(app)


def test_get_leases_returns_active(client: TestClient):
    r = client.get("/api/v1/eye-remote/leases")
    assert r.status_code == 200
    body = r.json()
    macs = {row["mac"] for row in body}
    assert macs == {"02:fb:00:00:11:03", "02:fb:00:00:d2:7f"}


def test_post_lease_event_records(client: TestClient):
    r = client.post(
        "/api/v1/eye-remote/lease-events",
        json={
            "action": "add",
            "mac": "02:fb:00:00:11:03",
            "ip": "10.55.0.11",
            "hostname": "eye-rpiz",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"status": "recorded"}


def test_post_lease_event_rejects_bad_mac(client: TestClient):
    r = client.post(
        "/api/v1/eye-remote/lease-events",
        json={"action": "add", "mac": "not-a-mac", "ip": "10.55.0.11"},
    )
    assert r.status_code == 422
