# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote leases router integration tests."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch, tmp_path: Path):
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
    from api.routers.leases import require_jwt

    # LA GARDE RESTE EN PLACE, ON PRESENTE UN PORTEUR VALIDE (#1256).
    #
    # Ces tests passaient auparavant SANS authentification : `leases.py` retombe
    # sur un `require_jwt` no-op quand `secubox_core` n'est pas importable
    # (repli « standalone Pi Zero »), et le harnais de test n'ajoutait pas
    # `common/` au chemin — les tests exercaient donc une app sans garde.
    # Maintenant que `common/` est sur le chemin, la vraie garde s'applique.
    #
    # `dependency_overrides` plutot qu'un faux jeton : on teste le ROUTEUR, pas
    # la cryptographie du jeton, et un test qui fabrique un JWT valide casserait
    # au prochain changement de secret.
    app.dependency_overrides[require_jwt] = lambda: None
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


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


def test_get_leases_resilient_to_malformed_reservations(monkeypatch, tmp_path):
    leases = tmp_path / "leases"
    leases.write_text(
        f"{int(__import__('time').time()) + 3600} 02:fb:00:00:11:03 10.55.0.11 host id\n"
    )
    res = tmp_path / "reservations.conf"
    res.write_text("not-a-valid-line\n")  # malformed → ValueError if not caught
    monkeypatch.setenv("SECUBOX_EYE_LEASE_FILE", str(leases))
    monkeypatch.setenv("SECUBOX_EYE_RESERVATIONS_FILE", str(res))

    from fastapi.testclient import TestClient
    from api.main import app
    from api.routers.leases import require_jwt

    # Ce test construit son propre client, hors de la fixture : meme surcharge.
    app.dependency_overrides[require_jwt] = lambda: None
    try:
        client = TestClient(app)
        r = client.get("/api/v1/eye-remote/leases")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200, r.text
    # Lease still shown, just with no joined hostname from reservations
    body = r.json()
    assert any(row["mac"] == "02:fb:00:00:11:03" for row in body)
