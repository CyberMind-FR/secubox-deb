# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.api tests — GET/POST /exposure/{vhost}."""
import sys
from pathlib import Path
from fastapi.testclient import TestClient
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common")); sys.path.insert(0, str(ROOT / "packages" / "secubox-exposure"))

def _client(tmp_path, monkeypatch, reload_ok=True):
    import api.reach as r
    import api.main as m
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path / "snip")
    monkeypatch.setattr(m, "_reload_nginx", lambda: reload_ok)     # no live reload in tests
    monkeypatch.setattr(m, "_apply_tor", _noop_apply_tor)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app)


async def _noop_apply_tor(vhost, want, user):
    return None

def test_post_sets_reach_and_writes_snippet(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.post("/exposure/z.example", json={"reach": "lan", "mesh": True, "tor": False})
    assert r.status_code == 200
    body = r.json()
    assert body["reach"] == "lan" and body["mesh"] is True
    snip = (tmp_path / "snip" / "z.example.conf").read_text()
    assert "allow 10.10.0.0/24;" in snip and "deny all;" in snip

def test_get_reflects_written_state(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    c.post("/exposure/z.example", json={"reach": "localhost", "mesh": False, "tor": False})
    got = c.get("/exposure/z.example").json()
    assert got["reach"] == "localhost"

def test_post_rejects_bad_reach(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.post("/exposure/z.example", json={"reach": "moon", "mesh": False, "tor": False}).status_code == 422

def test_post_rejects_vhost_with_dot_dot(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.post("/exposure/foo..bar", json={"reach": "lan", "mesh": False, "tor": False})
    assert r.status_code == 400

def test_get_rejects_invalid_vhost_name(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.get("/exposure/foo bar")
    assert r.status_code == 400


def test_set_exposure_rolls_back_and_500s_when_nginx_test_fails(tmp_path, monkeypatch):
    import api.main as m
    c = _client(tmp_path, monkeypatch, reload_ok=True)
    # seed a last-good snippet first
    r1 = c.post("/exposure/z.example", json={"reach": "lan", "mesh": False, "tor": False})
    assert r1.status_code == 200
    prev_content = (tmp_path / "snip" / "z.example.conf").read_text()

    # now flip nginx -t to fail for the next apply
    monkeypatch.setattr(m, "_reload_nginx", lambda: False)
    r2 = c.post("/exposure/z.example", json={"reach": "wan", "mesh": False, "tor": False})
    assert r2.status_code == 500

    # snippet rolled back to last-good content
    assert (tmp_path / "snip" / "z.example.conf").read_text() == prev_content


def test_set_exposure_rolls_back_to_absent_when_no_prior_snippet(tmp_path, monkeypatch):
    import api.main as m
    c = _client(tmp_path, monkeypatch, reload_ok=False)
    r = c.post("/exposure/new.example", json={"reach": "lan", "mesh": False, "tor": False})
    assert r.status_code == 500
    assert not (tmp_path / "snip" / "new.example.conf").exists()


def test_set_exposure_does_not_audit_when_reload_fails(tmp_path, monkeypatch):
    import api.main as m
    audits = []
    monkeypatch.setattr(m, "_audit_exposure", lambda vhost, rec, user: audits.append((vhost, rec)))
    c = _client(tmp_path, monkeypatch, reload_ok=False)
    r = c.post("/exposure/new.example", json={"reach": "lan", "mesh": False, "tor": False})
    assert r.status_code == 500
    assert audits == []


def test_set_exposure_audits_only_after_confirmed_reload(tmp_path, monkeypatch):
    import api.main as m
    audits = []
    monkeypatch.setattr(m, "_audit_exposure", lambda vhost, rec, user: audits.append((vhost, rec)))
    c = _client(tmp_path, monkeypatch, reload_ok=True)
    r = c.post("/exposure/z.example", json={"reach": "lan", "mesh": True, "tor": False})
    assert r.status_code == 200
    assert audits == [("z.example", {"vhost": "z.example", "reach": "lan", "mesh": True, "tor": False})]


def test_set_exposure_happy_path_writes_new_content_and_returns_record(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, reload_ok=True)
    r = c.post("/exposure/z.example", json={"reach": "wan", "mesh": False, "tor": False})
    assert r.status_code == 200
    assert r.json() == {"vhost": "z.example", "reach": "wan", "mesh": False, "tor": False}
    assert (tmp_path / "snip" / "z.example.conf").read_text() == ""
