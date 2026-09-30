# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ToolBoX — gardes des routes restaurées (#1778)
CyberMind — https://cybermind.fr

La toolbox est le portail kbin : uvicorn écoute 0.0.0.0:8088, HAProxy y
envoie le vhost PUBLIC kbin sans authentification, et le DNAT du tunnel
wg-toolbox y mène un pair directement. Les routes d'administration restaurées
ne doivent être atteignables ni depuis le vhost public, ni depuis un pair.

Les tests « socket » simulent un vrai pair : `TestClient(client=(ip, port))`
fixe l'adresse du socket, la seule que le client ne choisit pas.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from secubox_toolbox import api
from secubox_toolbox import sentinel_link as sl
from secubox_toolbox.app import app

PK_A = "PKApubkeyBASE64aaaaaaaaaaaaaaaaaaaaaaaaaaaa="
PK_B = "PKBpubkeyBASE64bbbbbbbbbbbbbbbbbbbbbbbbbbbb="
ADMIN = {"host": "admin.gk2.secubox.in"}
KBIN = {"host": "kbin.gk2.secubox.in"}

admin_client = TestClient(app)                              # derrière nginx
peer_a = TestClient(app, client=("10.99.1.5", 40000))       # DNAT du tunnel
stray_peer = TestClient(app, client=("10.99.1.77", 40000))  # absent de wg-peers.json


@pytest.fixture()
def peers(tmp_path, monkeypatch):
    p = tmp_path / "wg-peers.json"
    p.write_text(json.dumps({"peers": {
        PK_A: {"ip": "10.99.1.5", "label": "phone-A"},
        PK_B: {"ip": "10.99.1.6", "label": "phone-B"},
    }}))
    monkeypatch.setattr(api, "_RLEVEL_WG_PEERS", p)
    calls = []
    doc = {"defaults": {"mode": "passive", "floor": "passive"},
           "peers": {PK_A: {"chosen": "passive", "floor": "passive"},
                     PK_B: {"chosen": "passive", "floor": "passive"}}}

    def fake_ctl(args, timeout=15):
        calls.append(args)
        return (0, json.dumps(doc), "") if args[:1] == ["list"] else (0, "", "")

    monkeypatch.setattr(api, "_rlevel_ctl", fake_ctl)
    return calls


@pytest.fixture()
def tor_state(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "TOR_EXIT_CC", tmp_path / "cc.txt")
    monkeypatch.setattr(api, "TOR_VPN_CLIENTS", tmp_path / "vpn.txt")
    monkeypatch.setattr(api, "TOR_BRIDGES", tmp_path / "bridges.txt")
    monkeypatch.setattr(api, "_TOR_AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(api, "_trigger_reconcile", lambda: None)
    return tmp_path


# ── /rlevel admin : l'en-tête forgé ne blanchit plus un pair ─────────────

@pytest.mark.parametrize("hdr", [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "192.168.1.10, 127.0.0.1"},
    {"X-R3-Peer": "10.99.0.1"},
    {},
])
def test_peer_socket_cannot_reach_rlevel_admin_whatever_headers(peers, hdr):
    r = peer_a.get("/rlevel/peers", headers={**ADMIN, **hdr})
    assert r.status_code == 403
    r = peer_a.post("/rlevel/peer", headers={**ADMIN, **hdr},
                    json={"pubkey": PK_B, "forced": "off"})
    assert r.status_code == 403
    assert not [c for c in peers if c[:1] != ["list"]]  # aucune écriture


def test_unlisted_tunnel_address_is_still_a_peer(peers):
    """Un pair absent de wg-peers.json (fichier en retard) reste un pair."""
    assert stray_peer.get("/rlevel/peers", headers=ADMIN).status_code == 403


def test_any_forwarded_hop_naming_a_peer_is_refused(peers):
    r = admin_client.get("/rlevel/peers",
                         headers={**ADMIN, "X-Forwarded-For": "8.8.8.8, 10.99.1.6"})
    assert r.status_code == 403


def test_admin_vhost_still_works(peers):
    r = admin_client.get("/rlevel/peers", headers={**ADMIN, "X-Forwarded-For": "192.168.1.10"})
    assert r.status_code == 200
    assert {p["pubkey"] for p in r.json()["peers"]} == {PK_A, PK_B}


# ── /rlevel/me : l'identité ne s'emprunte pas ────────────────────────────

def test_rlevel_me_identity_is_the_socket_not_the_header(peers):
    r = peer_a.post("/rlevel/me", headers={"X-R3-Peer": "10.99.1.6",
                                           "X-Forwarded-For": "10.99.1.6"},
                    json={"chosen": "reel"})
    assert r.status_code == 200, r.text
    writes = [c for c in peers if c[:1] == ["set-chosen"]]
    assert writes == [["set-chosen", PK_A, "reel"]]  # A, jamais B


def test_rlevel_me_refused_on_public_kbin_vhost(peers):
    r = admin_client.get("/rlevel/me", headers={**KBIN, "X-R3-Peer": "10.99.1.6"})
    assert r.status_code == 403
    r = admin_client.post("/rlevel/me", headers={**KBIN, "X-R3-Peer": "10.99.1.6"},
                          json={"chosen": "reel"})
    assert r.status_code == 403
    assert not [c for c in peers if c[:1] == ["set-chosen"]]


def test_rlevel_me_direct_peer_works(peers):
    r = peer_a.get("/rlevel/me")
    assert r.status_code == 200
    assert r.json()["chosen"] == "passive"


# ── sortie Tor / VPN / ponts : ni kbin, ni pair ───────────────────────────

_TOR_CALLS = [
    ("get", "/exit_country", None),
    ("post", "/exit_country", {"countries": ["DE"]}),
    ("get", "/vpn/clients", None),
    ("post", "/vpn/client", {"kind": "ip", "selector": "10.99.1.5"}),
    ("delete", "/vpn/client", {"kind": "ip", "selector": "10.99.1.5"}),
    ("get", "/tor/bridges", None),
    ("post", "/tor/bridge", {"line": "Bridge obfs4 1.2.3.4:443 ABCDEF cert=x iat-mode=0"}),
    ("delete", "/tor/bridge", {"line": "Bridge obfs4 1.2.3.4:443 ABCDEF cert=x iat-mode=0"}),
]


def _call(client, verb, path, body, headers):
    if verb == "get":
        return client.get(path, headers=headers)
    return client.request(verb.upper(), path, headers=headers, json=body)


@pytest.mark.parametrize("verb,path,body", _TOR_CALLS)
def test_tor_routes_refused_on_kbin(peers, tor_state, verb, path, body):
    assert _call(admin_client, verb, path, body, KBIN).status_code == 403


@pytest.mark.parametrize("verb,path,body", _TOR_CALLS)
def test_tor_routes_refused_to_tunnel_peer(peers, tor_state, verb, path, body):
    assert _call(peer_a, verb, path, body, ADMIN).status_code == 403
    assert not (tor_state / "cc.txt").exists()
    assert not (tor_state / "vpn.txt").exists()
    assert not (tor_state / "bridges.txt").exists()


@pytest.mark.parametrize("verb,path,body", _TOR_CALLS)
def test_tor_routes_open_on_admin_vhost(peers, tor_state, verb, path, body):
    assert _call(admin_client, verb, path, body, ADMIN).status_code == 200


# ── liste blanche C2 de la sentinelle ────────────────────────────────────

@pytest.fixture()
def allow_spy(monkeypatch):
    seen = []
    monkeypatch.setattr(sl, "c2_allow", lambda h: seen.append(h) or True)
    return seen


def test_c2_allow_refused_on_kbin(peers, allow_spy):
    r = admin_client.post("/admin/sentinel/c2/allow", headers=KBIN, data={"host": "c2.evil"})
    assert r.status_code == 403 and not allow_spy


def test_c2_allow_refused_to_tunnel_peer(peers, allow_spy):
    r = peer_a.post("/admin/sentinel/c2/allow", headers=ADMIN, data={"host": "c2.evil"})
    assert r.status_code == 403 and not allow_spy


def test_c2_allow_open_on_admin_vhost(peers, allow_spy):
    r = admin_client.post("/admin/sentinel/c2/allow", headers=ADMIN, data={"host": "fp.example"})
    assert r.status_code == 200 and allow_spy == ["fp.example"]


# ── filtres MITM : écriture refusée sur kbin (garde d'origine) ────────────

@pytest.mark.parametrize("path", ["/admin/filter-control/toggle", "/admin/filter-control/delete"])
def test_filter_writes_refused_on_kbin(tmp_path, monkeypatch, path):
    monkeypatch.setattr(api, "MITM_FILTER_DISABLED_FILE", tmp_path / "disabled.txt")
    r = admin_client.post(path, headers=KBIN, json={"pattern": "example.com"})
    assert r.status_code == 403
    assert not (tmp_path / "disabled.txt").exists()


# ── ingestion SW-neuter : canal non authentifié, donc borné ──────────────

def test_sw_candidate_rejects_line_injection_and_junk(tmp_path, monkeypatch):
    f = tmp_path / "sw.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    r = admin_client.post("/__toolbox/sw-candidate", headers=KBIN, json={"hosts": [
        "ok.example.com", "evil.com\nsneaky.example", "no-dot", "a b.com", "HTTPS://x.com/"]})
    assert r.status_code == 204
    assert f.read_text().splitlines() == ["ok.example.com"]


def test_sw_candidate_file_is_capped(tmp_path, monkeypatch):
    f = tmp_path / "sw.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    monkeypatch.setattr(api, "_SW_CAND_FILE_MAX", 3)
    admin_client.post("/__toolbox/sw-candidate",
                      json={"hosts": [f"h{i}.example.com" for i in range(10)]})
    assert len(f.read_text().splitlines()) == 3


def test_sw_candidate_oversized_body_ignored(tmp_path, monkeypatch):
    f = tmp_path / "sw.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    monkeypatch.setattr(api, "_SW_CAND_BODY_MAX", 64)
    r = admin_client.post("/__toolbox/sw-candidate",
                          json={"hosts": [f"h{i}.example.com" for i in range(20)]})
    assert r.status_code == 204
    assert not f.exists()
