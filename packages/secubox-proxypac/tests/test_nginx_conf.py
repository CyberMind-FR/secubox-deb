# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_pac_route_sets_content_type_and_serves_state():
    conf = (ROOT / "nginx" / "proxypac.conf").read_text()
    assert "location = /proxy.pac" in conf
    assert "application/x-ns-proxy-autoconfig" in conf
    assert "/var/lib/secubox/proxypac/proxy.pac" in conf
    assert "/api/v1/proxypac/" in conf and "aggregator.sock" in conf
    # /proxy.pac must be LAN/mesh-gated even in the shared (public) server
    assert "deny all;" in conf
    assert "allow 10.10.0.0/24;" in conf

def test_wpad_vhost_is_lan_mesh_only():
    conf = (ROOT / "nginx" / "wpad-vhost.conf").read_text()
    assert "server_name wpad." in conf
    assert "allow 10.10.0.0/24;" in conf
    assert "deny all;" in conf
    assert "application/x-ns-proxy-autoconfig" in conf

def test_seed_rule_present():
    seed = (ROOT / "conf" / "rules.d" / "00-onion.rules").read_text()
    assert "*.onion socks5" in seed
