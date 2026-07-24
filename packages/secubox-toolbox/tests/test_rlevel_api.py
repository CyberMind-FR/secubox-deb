# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""API /rlevel — admin peer list + floor/force delegation, peer self-service
bounded by tunnel-IP identity (#rlevel-per-peer, task 6).

No in-process root: every write goes through `_rlevel_ctl` which shells out
to `sudo -n sbxmitm-policyctl` (task 4). Tests stub `_rlevel_ctl` directly for
behavioral assertions, and stub `subprocess.run` once to prove the real
delegation command line is well-formed.
"""
import json

from fastapi.testclient import TestClient

from secubox_toolbox.app import app
from secubox_toolbox import api

client = TestClient(app)

PK1 = "PK1pubkeyBASE64aaaaaaaaaaaaaaaaaaaaaaaaaaaa="
PK2 = "PK2pubkeyBASE64bbbbbbbbbbbbbbbbbbbbbbbbbbbb="


def _write_wg_peers(tmp_path, monkeypatch, peers: dict):
    p = tmp_path / "wg-peers.json"
    p.write_text(json.dumps({"peers": peers}))
    monkeypatch.setattr(api, "_RLEVEL_WG_PEERS", p)
    return p


def _stub_ctl(monkeypatch, doc=None, rc=0):
    """Stub _rlevel_ctl for 'list' calls; capture invocations."""
    calls = []
    doc = doc if doc is not None else {"defaults": {"mode": "passive", "floor": "passive"},
                                        "peers": {}}

    def fake(args, timeout=15):
        calls.append(args)
        if args and args[0] == "list":
            return rc, json.dumps(doc), ""
        return rc, "", "" if rc == 0 else "ctl error"

    monkeypatch.setattr(api, "_rlevel_ctl", fake)
    return calls


# ── admin: GET /rlevel/peers ────────────────────────────────────────────

def test_admin_list_peers_computes_effective(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {
        PK1: {"ip": "10.99.1.5", "label": "phone-A"},
        PK2: {"ip": "10.99.1.6", "label": "phone-B"},
    })
    doc = {
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {
            PK1: {"chosen": "active", "forced": None, "floor": "passive"},
            PK2: {"forced": "off", "chosen": "reel", "floor": "passive"},
        },
    }
    _stub_ctl(monkeypatch, doc=doc)

    r = client.get("/rlevel/peers")
    assert r.status_code == 200
    body = r.json()
    by_pk = {p["pubkey"]: p for p in body["peers"]}
    assert by_pk[PK1]["label"] == "phone-A"
    assert by_pk[PK1]["effective"] == "active"       # clamp(active, passive, reel)
    assert by_pk[PK2]["effective"] == "off"           # forced wins
    assert by_pk[PK1]["floor"] == "passive"


def test_admin_list_peers_unknown_peer_falls_back_to_defaults(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "new"}})
    _stub_ctl(monkeypatch, doc={"defaults": {"mode": "active", "floor": "passive"}, "peers": {}})
    r = client.get("/rlevel/peers")
    body = r.json()
    assert body["peers"][0]["chosen"] == "active"
    assert body["peers"][0]["effective"] == "active"


# ── admin: POST /rlevel/peer/{pubkey} ───────────────────────────────────

def test_admin_set_floor_delegates_to_real_ctl_command(monkeypatch):
    """Structural: the sudo command line actually invokes sbxmitm-policyctl."""
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    r = client.post(f"/rlevel/peer/{PK1}", json={"floor": "active"})
    assert r.status_code == 200, r.text
    assert "sudo" in captured["cmd"]
    assert "-n" in captured["cmd"]
    assert any("sbxmitm-policyctl" in c for c in captured["cmd"])
    assert "set-floor" in captured["cmd"]
    assert PK1 in captured["cmd"]
    assert "active" in captured["cmd"]


def test_admin_set_floor_and_force(monkeypatch):
    calls = _stub_ctl(monkeypatch)
    r = client.post(f"/rlevel/peer/{PK1}", json={"floor": "active", "forced": "reel"})
    assert r.status_code == 200
    assert ["set-floor", PK1, "active"] in calls
    assert ["force", PK1, "reel"] in calls


def test_admin_force_none_clears(monkeypatch):
    calls = _stub_ctl(monkeypatch)
    r = client.post(f"/rlevel/peer/{PK1}", json={"forced": None})
    assert r.status_code == 200
    assert ["force", PK1, "none"] in calls


def test_admin_set_invalid_floor_mode_400(monkeypatch):
    _stub_ctl(monkeypatch)
    r = client.post(f"/rlevel/peer/{PK1}", json={"floor": "bogus"})
    assert r.status_code == 400


def test_admin_set_empty_body_400(monkeypatch):
    _stub_ctl(monkeypatch)
    r = client.post(f"/rlevel/peer/{PK1}", json={})
    assert r.status_code == 400


def test_admin_ctl_failure_surfaces_502(monkeypatch):
    _stub_ctl(monkeypatch, rc=1)
    r = client.post(f"/rlevel/peer/{PK1}", json={"floor": "active"})
    assert r.status_code == 502


# ── peer: GET /rlevel/me ─────────────────────────────────────────────────

def test_me_resolves_via_tunnel_ip(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch, doc={
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {PK1: {"chosen": "active", "forced": None, "floor": "passive"}},
    })
    r = client.get("/rlevel/me", headers={"X-R3-Peer": "10.99.1.5"})
    assert r.status_code == 200
    body = r.json()
    assert body["chosen"] == "active"
    assert body["effective"] == "active"
    assert body["forced"] is None


def test_me_unknown_ip_403(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch)
    r = client.get("/rlevel/me", headers={"X-R3-Peer": "10.99.1.99"})
    assert r.status_code == 403


def test_me_no_ip_at_all_403(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {})
    _stub_ctl(monkeypatch)
    r = client.get("/rlevel/me")
    assert r.status_code == 403


# ── peer: POST /rlevel/me ────────────────────────────────────────────────

def test_post_me_valid_delegates_set_chosen(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    calls = _stub_ctl(monkeypatch, doc={
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {PK1: {"chosen": "passive", "forced": None, "floor": "passive"}},
    })
    r = client.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.5"}, json={"chosen": "active"})
    assert r.status_code == 200, r.text
    assert ["set-chosen", PK1, "active"] in calls


def test_post_me_below_floor_409(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch, doc={
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {PK1: {"chosen": "active", "forced": None, "floor": "active"}},
    })
    r = client.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.5"}, json={"chosen": "off"})
    assert r.status_code == 409


def test_post_me_cannot_lift_forced_409(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch, doc={
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {PK1: {"chosen": "passive", "forced": "off", "floor": "passive"}},
    })
    r = client.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.5"}, json={"chosen": "reel"})
    assert r.status_code == 409


def test_post_me_unknown_ip_403(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch)
    r = client.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.77"}, json={"chosen": "reel"})
    assert r.status_code == 403


def test_post_me_invalid_mode_400(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch, doc={
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {PK1: {"chosen": "passive", "forced": None, "floor": "passive"}},
    })
    r = client.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.5"}, json={"chosen": "bogus"})
    assert r.status_code == 400


def test_post_me_ctl_failure_surfaces_502(tmp_path, monkeypatch):
    _write_wg_peers(tmp_path, monkeypatch, {PK1: {"ip": "10.99.1.5", "label": "me"}})
    _stub_ctl(monkeypatch, doc={
        "defaults": {"mode": "passive", "floor": "passive"},
        "peers": {PK1: {"chosen": "passive", "forced": None, "floor": "passive"}},
    }, rc=1)
    r = client.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.5"}, json={"chosen": "active"})
    assert r.status_code == 502
