# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — CSPN parser tests (TDD)
CyberMind — https://cybermind.fr
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from posture import cspn  # noqa: E402


# ---- TLS minimum-version parsing ------------------------------------------

def test_tls_min_ok_when_old_tls_disabled():
    cfg = "global\n  ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11\n"
    assert cspn.tls_min_ok(cfg) is True


def test_tls_min_not_ok_when_tls10_allowed():
    cfg = "global\n  ssl-default-bind-options no-sslv3\n"
    assert cspn.tls_min_ok(cfg) is False


def test_tls_min_none_when_no_directive():
    assert cspn.tls_min_ok("global\n  maxconn 2000\n") is None


# ---- audit-log RFC3339 timestamp validation --------------------------------

def test_audit_timestamps_ok_iso8601():
    lines = [
        '2026-06-16T12:30:00+02:00 ban 1.2.3.4',
        '2026-06-16T12:31:05Z unban 5.6.7.8',
    ]
    assert cspn.audit_timestamps_ok(lines) is True


def test_audit_timestamps_not_ok_freeform():
    lines = ["Jun 16 12:30 something happened", "no timestamp here"]
    assert cspn.audit_timestamps_ok(lines) is False


def test_audit_timestamps_none_when_empty():
    assert cspn.audit_timestamps_ok([]) is None


# ---- nftables default-drop detection ---------------------------------------

def test_nft_default_drop_detected():
    out = "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n  }\n}"
    assert cspn.nft_has_drop_policy(out) is True


def test_nft_default_drop_absent_when_accept():
    out = "chain input {\n  type filter hook input priority 0; policy accept;\n}"
    assert cspn.nft_has_drop_policy(out) is False


def test_nft_default_drop_empty():
    assert cspn.nft_has_drop_policy("") is False


# ---- exposed listening ports count -----------------------------------------

def test_count_exposed_ports_counts_wildcard_only():
    ss_out = (
        "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        "LISTEN 0      4096   0.0.0.0:443        0.0.0.0:*\n"
        "LISTEN 0      4096   127.0.0.1:8088     0.0.0.0:*\n"
        "LISTEN 0      511    [::]:80            [::]:*\n"
    )
    # 0.0.0.0:443 and [::]:80 are externally exposed; 127.0.0.1 is not.
    assert cspn.count_exposed_ports(ss_out) == 2


def test_count_exposed_ports_zero_when_loopback_only():
    ss_out = "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 128 [::1]:631 [::]:*\n"
    assert cspn.count_exposed_ports(ss_out) == 0
