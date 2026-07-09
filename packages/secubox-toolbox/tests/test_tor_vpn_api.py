# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tor exit-country + VPN-client + obfs4-bridge CRUD (#683 follow-up):
validators + endpoint behavior, state paths and _trigger_reconcile mocked."""
import importlib

import pytest
from fastapi.testclient import TestClient


def _load(monkeypatch, tmp_path):
    import secubox_toolbox.api as m
    importlib.reload(m)
    monkeypatch.setattr(m, "TOR_EXIT_CC", tmp_path / "cc.txt")
    monkeypatch.setattr(m, "TOR_VPN_CLIENTS", tmp_path / "vpn.txt")
    monkeypatch.setattr(m, "TOR_BRIDGES", tmp_path / "bridges.txt")
    monkeypatch.setattr(m, "_TOR_AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(m, "_trigger_reconcile", lambda: None)
    return m


# ── validators — the security core ──────────────────────────────────────

def test_country_codes_validated(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    assert m._valid_cc("DE") and m._valid_cc("fr")
    assert not m._valid_cc("XXX") and not m._valid_cc("1")


def test_vpn_selector_validated(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    assert m._valid_selector("ip", "192.168.1.5") and m._valid_selector("cidr", "10.0.0.0/24")
    assert m._valid_selector("mac", "aa:bb:cc:dd:ee:ff")
    assert not m._valid_selector("ip", "1.2.3.999") and not m._valid_selector("mac", "zz")
    assert not m._valid_selector("bad", "x")


def test_bridge_line_validated(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    assert m._valid_bridge("Bridge obfs4 1.2.3.4:443 ABCDEF0123456789 cert=xyz iat-mode=0")
    assert not m._valid_bridge("obfs4 1.2.3.4:443 ABCDEF")  # missing "Bridge " prefix
    assert not m._valid_bridge("Bridge obfs4 rm -rf /; echo pwned")  # unsafe charset
    assert not m._valid_bridge("")
    assert not m._valid_bridge(None)


# ── endpoint behavior (TestClient, state paths + reconcile mocked) ──────

@pytest.fixture()
def client(monkeypatch, tmp_path):
    m = _load(monkeypatch, tmp_path)
    from secubox_toolbox.app import app
    return TestClient(app), m


def test_exit_country_get_empty(client):
    c, m = client
    r = c.get("/exit_country")
    assert r.status_code == 200
    assert r.json() == {"countries": []}


def test_exit_country_post_replaces_list(client):
    c, m = client
    r = c.post("/exit_country", json={"countries": ["de", "fr", "DE"]})
    assert r.status_code == 200
    assert r.json() == {"countries": ["DE", "FR"]}  # normalized + deduped
    assert m.TOR_EXIT_CC.read_text().splitlines() == ["DE", "FR"]
    r2 = c.get("/exit_country")
    assert r2.json() == {"countries": ["DE", "FR"]}


def test_exit_country_post_rejects_bad_code(client):
    c, m = client
    r = c.post("/exit_country", json={"countries": ["DE", "XXX"]})
    assert r.status_code == 400
    assert not m.TOR_EXIT_CC.exists()  # no partial write


def test_exit_country_post_rejects_non_list(client):
    c, m = client
    r = c.post("/exit_country", json={"countries": "DE"})
    assert r.status_code == 400


def test_vpn_client_add_list_remove(client):
    c, m = client
    assert c.get("/vpn/clients").json() == {"clients": []}
    r = c.post("/vpn/client", json={"kind": "ip", "selector": "192.168.1.5"})
    assert r.status_code == 200
    assert r.json() == {"clients": [{"kind": "ip", "selector": "192.168.1.5"}]}
    # duplicate add is a no-op (dedup)
    c.post("/vpn/client", json={"kind": "ip", "selector": "192.168.1.5"})
    assert c.get("/vpn/clients").json()["clients"] == [{"kind": "ip", "selector": "192.168.1.5"}]
    r = c.request("DELETE", "/vpn/client", json={"kind": "ip", "selector": "192.168.1.5"})
    assert r.status_code == 200
    assert r.json() == {"clients": []}
    assert c.get("/vpn/clients").json() == {"clients": []}


def test_vpn_client_rejects_bad_selector(client):
    c, m = client
    r = c.post("/vpn/client", json={"kind": "mac", "selector": "not-a-mac"})
    assert r.status_code == 400
    assert not m.TOR_VPN_CLIENTS.exists()


def test_tor_bridge_add_list_remove(client):
    c, m = client
    line = "Bridge obfs4 1.2.3.4:443 ABCDEF0123456789 cert=xyz iat-mode=0"
    assert c.get("/tor/bridges").json() == {"bridges": []}
    r = c.post("/tor/bridge", json={"line": line})
    assert r.status_code == 200
    assert r.json() == {"bridges": [line]}
    r = c.request("DELETE", "/tor/bridge", json={"line": line})
    assert r.status_code == 200
    assert r.json() == {"bridges": []}


def test_tor_bridge_rejects_bad_line(client):
    c, m = client
    r = c.post("/tor/bridge", json={"line": "not a bridge line"})
    assert r.status_code == 400
    assert not m.TOR_BRIDGES.exists()


def test_mutations_are_audited(client):
    c, m = client
    c.post("/exit_country", json={"countries": ["DE"]})
    assert m._TOR_AUDIT_LOG.exists()
    txt = m._TOR_AUDIT_LOG.read_text()
    assert "exit_country_set" in txt and "DE" in txt
