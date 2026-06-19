# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Phase 6 (#662) — per-client country flag from the REAL external WG endpoint IP."""
import asyncio
import hashlib
from types import SimpleNamespace

from secubox_toolbox import api
from secubox_toolbox import wg


# A `wg show wg-toolbox dump` blob. First line = interface (skipped).
# Peer fields are TAB-separated: pubkey  psk  endpoint  allowed-ips  ...
_PUB_PUBLIC = "cVZ7s8d2pubkeyAAAAAAAAAAAAAAAAAAAAAAAAAAAA="   # real public endpoint
_PUB_NONE = "noneZZZpubkeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="     # endpoint (none)
_PUB_LAN = "lanZZZZZpubkeyCCCCCCCCCCCCCCCCCCCCCCCCCCCC="      # RFC1918 endpoint
_PUB_V6 = "v6ZZZZZZpubkeyDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="      # IPv6 endpoint

_DUMP = "\t".join([
    "srvPrivKey", "srvPubKey", "51820", "off",
]) + "\n" + "\n".join([
    "\t".join([_PUB_PUBLIC, "(none)", "88.163.66.208:51820", "10.99.1.2/32", "0", "0", "0"]),
    "\t".join([_PUB_NONE, "(none)", "(none)", "10.99.1.3/32", "0", "0", "0"]),
    "\t".join([_PUB_LAN, "(none)", "192.168.1.50:41234", "10.99.1.4/32", "0", "0", "0"]),
    "\t".join([_PUB_V6, "(none)", "[2606:4700:4700::1111]:51820", "10.99.1.5/32", "0", "0", "0"]),
])


def _hash(pub: str) -> str:
    return hashlib.sha256(pub.encode()).hexdigest()[:16]


def _fake_run(blob):
    def _run(cmd, **kw):
        return SimpleNamespace(stdout=blob, stderr="", returncode=0)
    return _run


def test_wg_endpoints_parsing(monkeypatch):
    # Bust the 30s cache between tests.
    wg._ENDPOINTS_CACHE, wg._ENDPOINTS_TS = {}, 0.0
    monkeypatch.setattr(wg.subprocess, "run", _fake_run(_DUMP))

    eps = wg.wg_endpoints()

    # Public IPv4 endpoint → mapped, port stripped.
    assert eps[_hash(_PUB_PUBLIC)] == "88.163.66.208"
    # mac_hash derivation matches the known pubkey→hash.
    assert _hash(_PUB_PUBLIC) == "ad32e736309b1348"
    # IPv6 endpoint → bracket + port stripped (global IPv6 kept).
    assert eps[_hash(_PUB_V6)] == "2606:4700:4700::1111"
    # `(none)` endpoint skipped.
    assert _hash(_PUB_NONE) not in eps
    # RFC1918 LAN endpoint skipped (no meaningful country).
    assert _hash(_PUB_LAN) not in eps


def test_wg_endpoints_besteffort_empty(monkeypatch):
    wg._ENDPOINTS_CACHE, wg._ENDPOINTS_TS = {}, 0.0

    def _boom(*a, **k):
        raise FileNotFoundError("wg not installed")

    monkeypatch.setattr(wg.subprocess, "run", _boom)
    assert wg.wg_endpoints() == {}


def test_clients_rich_uses_external_endpoint_flag(monkeypatch):
    wg_pub = "clientPubKeyEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
    wg_mac = _hash(wg_pub)
    rows = [
        # WG client: stored ip is internal 10.99.1.x, has a public endpoint.
        {"mac_hash": wg_mac, "ip": "10.99.1.7", "state": "active",
         "level": "r3", "score": 0, "last_seen": 100.0, "first_seen": 0.0},
        # Non-WG / captive client: no endpoint → falls back to stored ip.
        {"mac_hash": "captive01", "ip": "203.0.113.9", "state": "active",
         "level": "r1", "score": 0, "last_seen": 50.0, "first_seen": 0.0},
    ]
    monkeypatch.setattr(api.store, "list_clients", lambda: rows)
    monkeypatch.setattr(api.store, "latest_user_agent", lambda mh: "")

    # External endpoint for the WG client only. admin_clients_rich does a lazy
    # `from . import wg`, so patching the wg module attribute is what takes effect.
    import secubox_toolbox.wg as _wgmod
    monkeypatch.setattr(_wgmod, "wg_endpoints", lambda: {wg_mac: "88.163.66.208"})

    seen_keys = []

    def fake_lookup(key):
        seen_keys.append(key)
        if key == "88.163.66.208":
            return {"flag": "🇫🇷", "country_iso": "FR", "asn_org": "Orange"}
        if key == "203.0.113.9":
            return {"flag": "🇺🇸", "country_iso": "US", "asn_org": "Example"}
        return {"flag": "", "country_iso": "", "asn_org": ""}

    monkeypatch.setattr(api.geo, "lookup", fake_lookup)

    out = asyncio.run(api.admin_clients_rich())
    clients = {c["mac_hash"]: c for c in out["clients"]}

    # WG client: flag derived from the EXTERNAL IP, not the internal 10.99.1.7.
    assert clients[wg_mac]["flag"] == "🇫🇷"
    assert clients[wg_mac]["country_iso"] == "FR"
    assert "88.163.66.208" in seen_keys
    assert "10.99.1.7" not in seen_keys  # internal IP never geo-looked-up

    # Non-WG client: falls back to the stored ip.
    assert clients["captive01"]["flag"] == "🇺🇸"
    assert "203.0.113.9" in seen_keys

    # PRIVACY: the raw external IP must NOT appear anywhere in the response.
    import json
    dumped = json.dumps(out, default=str)
    assert "88.163.66.208" not in dumped
    # The stored (internal) ip is still the only ip field exposed.
    assert clients[wg_mac]["ip"] == "10.99.1.7"
